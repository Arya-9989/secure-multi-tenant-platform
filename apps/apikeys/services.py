"""Issuing, rotating, revoking and authenticating API keys (ADR 0005)."""

from __future__ import annotations

import hmac
import logging
import re
import secrets
from datetime import timedelta

from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from apps.accounts.models import User
from apps.accounts.roles import ApiScope, Perm
from apps.apikeys.models import KEY_PREFIX, ApiKey, hash_secret
from apps.auditlogs.models import AuditAction
from apps.auditlogs.services import record
from apps.common import rls
from apps.common.context import get_request_context
from apps.common.guards import require_permission, require_same_tenant
from apps.common.principals import ServicePrincipal
from apps.organizations.models import Organization

logger = logging.getLogger(__name__)

MAX_LIFETIME_DAYS = 365
MAX_GRACE_MINUTES = 1440
LAST_USED_RESOLUTION = timedelta(minutes=1)
_PREFIX = re.compile(r"[0-9a-f]{12}")
# Compared against when the prefix is unknown, so both paths hash and compare.
_DUMMY_HASH = hash_secret("not-a-real-key")


def _mint() -> tuple[str, str, str]:
    prefix, secret = secrets.token_hex(6), secrets.token_urlsafe(32)
    return prefix, secret, f"{KEY_PREFIX}_{prefix}_{secret}"


def _issue(
    *,
    actor: User,
    organization: Organization,
    name: str,
    scopes: list[str],
    days: int,
    rotated_from: ApiKey | None = None,
) -> tuple[ApiKey, str]:
    prefix, secret, full = _mint()
    now = timezone.now()
    key = ApiKey.objects.create(
        organization=organization,
        name=name,
        prefix=prefix,
        secret_hash=hash_secret(secret),
        scopes=sorted(set(scopes)),
        created_by=actor,
        created_at=now,
        expires_at=now + timedelta(days=days),
        rotated_from=rotated_from,
    )
    return key, full


def create_key(
    *,
    actor: User,
    organization: Organization,
    name: str,
    scopes: list[str],
    expires_in_days: int,
) -> tuple[ApiKey, str]:
    """Issue a key; the full value is returned here and never again."""
    require_permission(actor, Perm.API_KEY_MANAGE)
    require_same_tenant(actor, organization)
    if not organization.is_active:
        raise ValidationError({"organization": ["This organization is inactive."]})
    unknown = set(scopes) - {scope.value for scope in ApiScope}
    if not scopes or unknown:
        raise ValidationError({"scopes": ["Choose one or more of the read scopes."]})
    if not 1 <= expires_in_days <= MAX_LIFETIME_DAYS:
        raise ValidationError({"expires_in_days": [f"Between 1 and {MAX_LIFETIME_DAYS}."]})
    with transaction.atomic():
        key, full = _issue(
            actor=actor, organization=organization, name=name, scopes=scopes, days=expires_in_days
        )
        record(
            AuditAction.API_KEY_CREATED,
            actor=actor,
            organization=organization,
            target=key,
            metadata={"name": name, "prefix": key.prefix, "scopes": key.scopes},
        )
    return key, full


def _lock_active(key: ApiKey) -> ApiKey:
    locked = ApiKey.objects.select_for_update().select_related("organization").get(pk=key.pk)
    if locked.status != "active":
        raise ValidationError({"detail": "Only an active key can be changed."})
    return locked


def revoke_key(*, actor: User, key: ApiKey) -> ApiKey:
    require_permission(actor, Perm.API_KEY_MANAGE)
    require_same_tenant(actor, key)
    with transaction.atomic():
        key = _lock_active(key)
        key.revoked_at, key.revoked_by = timezone.now(), actor
        key.save(update_fields=["revoked_at", "revoked_by"])
        record(
            AuditAction.API_KEY_REVOKED,
            actor=actor,
            organization=key.organization,
            target=key,
            metadata={"prefix": key.prefix},
        )
    return key


def rotate_key(*, actor: User, key: ApiKey, grace_minutes: int) -> tuple[ApiKey, str]:
    """A new key with the same name and scopes; the old one works ``grace_minutes`` more."""
    require_permission(actor, Perm.API_KEY_MANAGE)
    require_same_tenant(actor, key)
    if not 0 <= grace_minutes <= MAX_GRACE_MINUTES:
        raise ValidationError({"grace_minutes": [f"Between 0 and {MAX_GRACE_MINUTES}."]})
    with transaction.atomic():
        old = _lock_active(key)
        now = timezone.now()
        lifetime_days = max(1, (old.expires_at - old.created_at).days)
        new, full = _issue(
            actor=actor,
            organization=old.organization,
            name=old.name,
            scopes=list(old.scopes),
            days=min(lifetime_days, MAX_LIFETIME_DAYS),
            rotated_from=old,
        )
        if grace_minutes == 0:
            old.revoked_at, old.revoked_by = now, actor
        else:
            old.expires_at = min(old.expires_at, now + timedelta(minutes=grace_minutes))
        old.save(update_fields=["revoked_at", "revoked_by", "expires_at"])
        record(
            AuditAction.API_KEY_ROTATED,
            actor=actor,
            organization=old.organization,
            target=new,
            metadata={"from": old.prefix, "to": new.prefix, "grace_minutes": grace_minutes},
        )
    return new, full


def authenticate(raw: str) -> tuple[ServicePrincipal, rls.DbScope] | None:
    """The principal for a presented key, or ``None`` (deliberately unspecific)."""
    kind, _, rest = raw.partition("_")
    prefix, _, secret = rest.partition("_")
    if kind != KEY_PREFIX or not _PREFIX.fullmatch(prefix) or not secret:
        return None
    with rls.platform_scope():  # pre-authentication: learn only the key's tenant
        organization_id = (
            ApiKey.objects.filter(prefix=prefix).values_list("organization_id", flat=True).first()
        )
    scope = rls.for_tenant(organization_id)
    with rls.scope(scope):
        key = ApiKey.objects.select_related("organization").filter(prefix=prefix).first()
        presented = hash_secret(secret)
        matches = hmac.compare_digest(key.secret_hash if key else _DUMMY_HASH, presented)
        if key is None or not matches or key.status != "active" or not key.organization.is_active:
            logger.info("API key rejected", extra={"prefix": prefix})
            return None
        _touch(key)
    principal = ServicePrincipal(
        key_id=key.pk,
        key_prefix=prefix,
        organization_id=key.organization_id,
        scopes=frozenset(key.scopes),
    )
    return principal, scope


def _touch(key: ApiKey) -> None:
    """Record the last use, at most once per minute (most requests write nothing)."""
    now = timezone.now()
    context = get_request_context()
    ApiKey.objects.filter(pk=key.pk).filter(
        Q(last_used_at__isnull=True) | Q(last_used_at__lt=now - LAST_USED_RESOLUTION)
    ).update(last_used_at=now, last_used_ip=context.ip_address if context else None)
