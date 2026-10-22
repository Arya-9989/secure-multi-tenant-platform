"""Business rules for users, sessions and invitations.

Every function that mutates state:

* re-checks the actor's permission and tenant (see :mod:`apps.common.guards`),
* runs in a transaction, locking rows in a consistent order
  (organization -> user) so concurrent admin changes cannot race past the
  "at least one active admin" invariant,
* writes its audit record inside the same transaction.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.mail import send_mail
from django.db import transaction
from django.db.models import F
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.settings import api_settings as jwt_settings
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

from apps.accounts.authentication import TenantRefreshToken
from apps.accounts.models import (
    Invitation,
    InvitationStatus,
    User,
    hash_invitation_token,
    normalize_email,
)
from apps.accounts.roles import ASSIGNABLE_ROLES, Perm, Role
from apps.auditlogs.models import AuditAction
from apps.auditlogs.services import record
from apps.common.guards import require_permission, require_same_tenant
from apps.organizations.models import Organization

logger = logging.getLogger(__name__)

INVALID_INVITATION = "This invitation is invalid or has expired."


# ---------------------------------------------------------------- sessions
def revoke_all_tokens(user: User) -> None:
    """Invalidate every access and refresh token issued to ``user`` so far."""
    User.objects.filter(pk=user.pk).update(token_version=F("token_version") + 1)
    user.refresh_from_db(fields=["token_version"])
    outstanding = OutstandingToken.objects.filter(user=user, blacklistedtoken__isnull=True)
    BlacklistedToken.objects.bulk_create(
        [BlacklistedToken(token=token) for token in outstanding], ignore_conflicts=True
    )


def logout(user: User, raw_refresh_token: str) -> None:
    invalid = ValidationError({"refresh": ["Token is invalid or expired."]})
    try:
        token = TenantRefreshToken(raw_refresh_token)  # type: ignore[arg-type]
    except TokenError as exc:
        raise invalid from exc
    # Never let one user blacklist another user's session.
    if str(token.get(jwt_settings.USER_ID_CLAIM)) != str(user.pk):
        raise invalid
    with transaction.atomic():
        token.blacklist()
        record(AuditAction.LOGOUT, actor=user, organization=user.organization)


def logout_everywhere(user: User) -> None:
    with transaction.atomic():
        revoke_all_tokens(user)
        record(AuditAction.LOGOUT_ALL, actor=user, organization=user.organization)


def change_password(user: User, *, current_password: str, new_password: str) -> None:
    if not user.check_password(current_password):
        raise ValidationError({"current_password": ["Current password is incorrect."]})
    _validate_password(new_password, user)
    with transaction.atomic():
        user.set_password(new_password)
        user.save(update_fields=["password", "updated_at"])
        revoke_all_tokens(user)
        record(
            AuditAction.PASSWORD_CHANGED, actor=user, organization=user.organization, target=user
        )


def update_profile(user: User, *, changes: dict[str, Any]) -> User:
    changed = {k: v for k, v in changes.items() if getattr(user, k) != v}
    if not changed:
        return user
    with transaction.atomic():
        for field, value in changed.items():
            setattr(user, field, value)
        user.save(update_fields=[*changed, "updated_at"])
        record(
            AuditAction.USER_PROFILE_UPDATED,
            actor=user,
            organization=user.organization,
            target=user,
            metadata={"fields": sorted(changed)},
        )
    return user


# ---------------------------------------------------------------- user administration
def _check_can_administer(actor: User, target: User) -> None:
    require_permission(actor, Perm.USER_MANAGE)
    require_same_tenant(actor, target)
    if target.is_super_admin:
        raise PermissionDenied("Super admin accounts can only be managed from the command line.")
    if target.pk == actor.pk:
        raise PermissionDenied("You cannot change your own role or account status.")


def _lock(target: User) -> User:
    """Lock the target's organization row, then the target row (fixed order)."""
    if target.organization_id is not None:
        Organization.objects.select_for_update().filter(pk=target.organization_id).first()
    locked: User = (
        User.objects.select_for_update(of=("self",))
        .select_related("organization")
        .get(pk=target.pk)
    )
    return locked


def _ensure_another_active_admin(target: User) -> None:
    others = User.objects.filter(
        organization=target.organization, role=Role.ORG_ADMIN, is_active=True
    ).exclude(pk=target.pk)
    if not others.exists():
        raise ValidationError(
            {"detail": "An organization must keep at least one active organization admin."}
        )


def change_role(*, actor: User, target: User, new_role: str) -> User:
    _check_can_administer(actor, target)
    if new_role not in ASSIGNABLE_ROLES:
        raise ValidationError({"role": [f'"{new_role}" is not an assignable role.']})
    with transaction.atomic():
        target = _lock(target)
        old_role = target.role
        if old_role == new_role:
            return target
        if old_role == Role.ORG_ADMIN and target.is_active:
            _ensure_another_active_admin(target)
        target.role = new_role
        target.save(update_fields=["role", "updated_at"])
        record(
            AuditAction.USER_ROLE_CHANGED,
            actor=actor,
            organization=target.organization,
            target=target,
            metadata={"from": old_role, "to": new_role},
        )
    return target


def deactivate_user(*, actor: User, target: User) -> User:
    _check_can_administer(actor, target)
    with transaction.atomic():
        target = _lock(target)
        if not target.is_active:
            return target
        if target.role == Role.ORG_ADMIN:
            _ensure_another_active_admin(target)
        target.is_active = False
        target.deactivated_at = timezone.now()
        target.save(update_fields=["is_active", "deactivated_at", "updated_at"])
        revoke_all_tokens(target)
        record(
            AuditAction.USER_DEACTIVATED,
            actor=actor,
            organization=target.organization,
            target=target,
        )
    return target


def reactivate_user(*, actor: User, target: User) -> User:
    _check_can_administer(actor, target)
    with transaction.atomic():
        target = _lock(target)
        if target.is_active:
            return target
        target.is_active = True
        target.deactivated_at = None
        target.save(update_fields=["is_active", "deactivated_at", "updated_at"])
        record(
            AuditAction.USER_REACTIVATED,
            actor=actor,
            organization=target.organization,
            target=target,
        )
    return target


# ---------------------------------------------------------------- invitations
def build_accept_url(raw_token: str) -> str:
    return settings.FRONTEND_INVITE_URL.format(token=raw_token)


def create_invitation(
    *, actor: User, organization: Organization, email: str, role: str
) -> tuple[Invitation, str]:
    """Create an invitation and return it with the raw token (shown exactly once)."""
    require_permission(actor, Perm.INVITATION_MANAGE)
    require_same_tenant(actor, organization)
    if role not in ASSIGNABLE_ROLES:
        raise ValidationError({"role": [f'"{role}" is not an assignable role.']})
    if not organization.is_active:
        raise ValidationError({"organization": ["This organization is inactive."]})
    email = normalize_email(email)
    # Only same-tenant membership is reported. An address registered in a
    # *different* organization is not revealed here (that would let an org
    # admin probe other tenants); acceptance fails generically instead.
    if User.objects.filter(email=email, organization=organization).exists():
        raise ValidationError({"email": ["This person is already a member of the organization."]})

    now = timezone.now()
    with transaction.atomic():
        existing = (
            Invitation.objects.open()
            .select_for_update()
            .filter(organization=organization, email=email)
            .first()
        )
        if existing is not None:
            if existing.status == InvitationStatus.PENDING:
                raise ValidationError(
                    {"email": ["A pending invitation already exists for this email."]}
                )
            existing.revoked_at, existing.revoked_by = now, actor  # supersede expired invite
            existing.save(update_fields=["revoked_at", "revoked_by"])

        raw_token = secrets.token_urlsafe(32)
        invitation = Invitation.objects.create(
            organization=organization,
            email=email,
            role=role,
            token_hash=hash_invitation_token(raw_token),
            invited_by=actor,
            expires_at=now + settings.INVITATION_TTL,
        )
        record(
            AuditAction.INVITATION_CREATED,
            actor=actor,
            organization=organization,
            target=invitation,
            metadata={"email": email, "role": role},
        )
        transaction.on_commit(lambda: _send_invitation_email(invitation, raw_token))
    return invitation, raw_token


def _send_invitation_email(invitation: Invitation, raw_token: str) -> None:
    try:
        send_mail(
            subject=f"You have been invited to {invitation.organization.name}",
            message=(
                f"You have been invited to join {invitation.organization.name} as "
                f"{invitation.get_role_display()}.\n\n"
                f"Accept the invitation: {build_accept_url(raw_token)}\n\n"
                f"This link expires at {invitation.expires_at:%Y-%m-%d %H:%M} UTC."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[invitation.email],
        )
    except Exception:  # the invitation is still valid; the admin can share the link
        logger.exception("Failed to send invitation email", extra={"invitation": invitation.pk})


def revoke_invitation(*, actor: User, invitation: Invitation) -> Invitation:
    require_permission(actor, Perm.INVITATION_MANAGE)
    require_same_tenant(actor, invitation)
    with transaction.atomic():
        invitation = Invitation.objects.select_for_update().get(pk=invitation.pk)
        if invitation.status != InvitationStatus.PENDING:
            raise ValidationError({"detail": "Only pending invitations can be revoked."})
        invitation.revoked_at, invitation.revoked_by = timezone.now(), actor
        invitation.save(update_fields=["revoked_at", "revoked_by"])
        record(
            AuditAction.INVITATION_REVOKED,
            actor=actor,
            organization=invitation.organization,
            target=invitation,
        )
    return invitation


def accept_invitation(*, raw_token: str, password: str, full_name: str = "") -> User:
    invalid = ValidationError({"token": [INVALID_INVITATION]})
    with transaction.atomic():
        invitation = (
            Invitation.objects.select_for_update(of=("self",))
            .select_related("organization")
            .filter(token_hash=hash_invitation_token(raw_token))
            .first()
        )
        if (
            invitation is None
            or invitation.status != InvitationStatus.PENDING
            or not invitation.organization.is_active
            or User.objects.filter(email=invitation.email).exists()
        ):
            raise invalid

        user = User(
            email=invitation.email,
            full_name=full_name,
            role=invitation.role,
            organization=invitation.organization,
        )
        _validate_password(password, user)
        user.set_password(password)
        user.save()
        invitation.accepted_at, invitation.accepted_user = timezone.now(), user
        invitation.save(update_fields=["accepted_at", "accepted_user"])
        record(
            AuditAction.INVITATION_ACCEPTED,
            actor=user,
            organization=invitation.organization,
            target=invitation,
            metadata={"role": invitation.role},
        )
    return user


def _validate_password(password: str, user: User) -> None:
    try:
        validate_password(password, user=user)
    except DjangoValidationError as exc:
        raise ValidationError({"password": list(exc.messages)}) from exc
