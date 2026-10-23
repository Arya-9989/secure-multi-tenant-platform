"""Login sessions as refresh-token families, with reuse detection (ADR 0002).

Every sign-in starts a :class:`RefreshTokenFamily`. Its refresh tokens carry the
family's ID (``fam``), their own ID (``jti``) and their generation (``gen``);
the family remembers only the ID of the one token that may be redeemed next.

* Rotation is a compare-and-swap on that ID, so of any number of concurrent
  requests exactly one moves the family forward.
* A validly signed token of a live family whose ID is no longer current can
  only be an older token coming back: either the client or a thief is replaying
  it. The whole family is revoked and the event audited.
* Access tokens carry ``fam`` too, and authentication checks that the family is
  still live, so ending a session ends its access tokens at once.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime

from django.conf import settings
from django.db import transaction
from django.db.models import F, QuerySet
from django.utils import timezone
from rest_framework_simplejwt.settings import api_settings as jwt_settings
from rest_framework_simplejwt.utils import datetime_to_epoch

from apps.accounts.authentication import (
    FAMILY_CLAIM,
    GENERATION_CLAIM,
    TenantRefreshToken,
    family_id_of,
)
from apps.accounts.models import RefreshTokenFamily, SessionEndReason, User
from apps.auditlogs.models import AuditAction
from apps.auditlogs.services import record
from apps.common.context import get_request_context

logger = logging.getLogger(__name__)


class InvalidSessionError(Exception):
    """The refresh token cannot be redeemed (deliberately unspecific)."""


def _new_jti() -> str:
    return uuid.uuid4().hex


def start(user: User) -> TenantRefreshToken:
    """Open a new session for ``user`` and return its first refresh token."""
    context = get_request_context()
    family = RefreshTokenFamily.objects.create(
        user=user,
        organization_id=user.organization_id,
        current_jti=_new_jti(),
        expires_at=timezone.now() + settings.JWT_SESSION_MAX_AGE,
        ip_address=context.ip_address if context else None,
        user_agent=context.user_agent if context else "",
    )
    return _token_for(user, family)


def _token_for(user: User, family: RefreshTokenFamily) -> TenantRefreshToken:
    token = TenantRefreshToken.for_user(user)
    token[jwt_settings.JTI_CLAIM] = family.current_jti
    token[FAMILY_CLAIM] = str(family.pk)
    token[GENERATION_CLAIM] = family.generation
    # No refresh token outlives the session it belongs to.
    token["exp"] = min(token["exp"], datetime_to_epoch(family.expires_at))
    return token


def rotate(token: TenantRefreshToken, user: User) -> TenantRefreshToken:
    """Exchange a refresh token for its successor, or detect that it was replayed.

    Raises :class:`InvalidSessionError` for anything that is not the family's
    current token, after revoking the family if that is reuse.
    """
    family_id = family_id_of(token)
    if family_id is None:
        raise InvalidSessionError
    presented = str(token[jwt_settings.JTI_CLAIM])
    now = timezone.now()
    with transaction.atomic():
        moved = RefreshTokenFamily.objects.filter(
            pk=family_id,
            user=user,
            current_jti=presented,
            revoked_at__isnull=True,
            expires_at__gt=now,
        ).update(current_jti=_new_jti(), generation=F("generation") + 1, last_refreshed_at=now)
    if moved:
        return _token_for(user, RefreshTokenFamily.objects.get(pk=family_id))
    _revoke_if_reused(family_id, user, token, now)
    raise InvalidSessionError


def _revoke_if_reused(
    family_id: uuid.UUID, user: User, token: TenantRefreshToken, now: datetime
) -> None:
    family = RefreshTokenFamily.objects.filter(pk=family_id, user=user).first()
    if family is None or not family.is_live:
        return  # unknown, ended or expired: simply invalid
    with transaction.atomic():
        # Conditional, so that of many racing replays exactly one records the event.
        revoked = RefreshTokenFamily.objects.filter(pk=family.pk, revoked_at__isnull=True).update(
            revoked_at=now, revoked_reason=SessionEndReason.REUSE_DETECTED
        )
        if not revoked:
            return
        record(
            AuditAction.REFRESH_TOKEN_REUSE_DETECTED,
            organization=user.organization,
            target=user,
            metadata={
                "session": str(family.pk),
                "presented_generation": token.get(GENERATION_CLAIM),
                "current_generation": family.generation,
            },
        )
    logger.warning(
        "Refresh token reuse detected; session revoked",
        extra={"session": str(family.pk), "user_id": str(user.pk)},
    )


def end(user: User, token: TenantRefreshToken, reason: SessionEndReason) -> bool:
    """End the session ``token`` belongs to. ``False`` if it was not live."""
    family_id = family_id_of(token)
    if family_id is None:
        return False
    return bool(
        RefreshTokenFamily.objects.filter(pk=family_id, user=user)
        .live()
        .update(revoked_at=timezone.now(), revoked_reason=reason)
    )


def end_all(users: QuerySet[User], reason: SessionEndReason) -> int:
    """End every live session of these users."""
    return RefreshTokenFamily.objects.filter(user__in=users, revoked_at__isnull=True).update(
        revoked_at=timezone.now(), revoked_reason=reason
    )
