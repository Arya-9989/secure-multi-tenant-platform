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
from django.db import IntegrityError, transaction
from django.db.models import F, QuerySet
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.settings import api_settings as jwt_settings

from apps.accounts import sessions
from apps.accounts.authentication import TenantRefreshToken
from apps.accounts.models import (
    EmailStatus,
    Invitation,
    InvitationStatus,
    SessionEndReason,
    User,
    hash_invitation_token,
    normalize_email,
)
from apps.accounts.roles import ASSIGNABLE_ROLES, Perm, Role
from apps.accounts.scopes import scope_for_account, scope_for_invitation
from apps.auditlogs.models import AuditAction
from apps.auditlogs.services import record
from apps.common import crypto, rls
from apps.common.guards import require_permission, require_same_tenant
from apps.organizations.models import Organization

logger = logging.getLogger(__name__)

INVALID_INVITATION = "This invitation is invalid or has expired."


# ---------------------------------------------------------------- sessions
def record_failed_login(email: str, *, channel: str | None = None, delay: int = 0) -> None:
    """Audit a failed sign-in (API or admin) without revealing whether the account exists."""
    email = normalize_email(email)[:254]
    # Attributed to the targeted account's tenant so its admins can see attacks
    # on their users; attempts against unknown emails are platform-level events,
    # the one write before authentication that needs platform scope.
    account_scope = scope_for_account(email=email) if email else rls.NO_SCOPE
    with rls.scope(rls.PLATFORM if account_scope == rls.NO_SCOPE else account_scope):
        known = (
            User.objects.select_related("organization").filter(email=email).first()
            if email
            else None
        )
        metadata: dict[str, str | int] = {"email": email}
        if channel:
            metadata["channel"] = channel
        if delay:  # this failure started a per-account delay (ADR 0003)
            metadata["next_attempt_delay"] = delay
        record(
            AuditAction.LOGIN_FAILED,
            organization=known.organization if known else None,
            target=known,
            metadata=metadata,
        )


def revoke_all_tokens(user: User, reason: SessionEndReason) -> None:
    """Invalidate every access and refresh token issued to ``user`` so far."""
    revoke_tokens_of(User.objects.filter(pk=user.pk), reason)
    user.refresh_from_db(fields=["token_version"])


def revoke_tokens_of(users: QuerySet[User], reason: SessionEndReason) -> None:
    """Invalidate every access and refresh token issued to these users so far."""
    users.update(token_version=F("token_version") + 1)
    sessions.end_all(users, reason)


def logout(user: User, raw_refresh_token: str) -> None:
    """End the session the refresh token belongs to; its access tokens die with it."""
    invalid = ValidationError({"refresh": ["Token is invalid or expired."]})
    try:
        token = TenantRefreshToken(raw_refresh_token)  # type: ignore[arg-type]
    except TokenError as exc:
        raise invalid from exc
    # Never let one user end another user's session.
    if str(token.get(jwt_settings.USER_ID_CLAIM)) != str(user.pk):
        raise invalid
    with transaction.atomic():
        if not sessions.end(user, token, SessionEndReason.LOGOUT):
            raise invalid
        record(AuditAction.LOGOUT, actor=user, organization=user.organization)


def logout_everywhere(user: User) -> None:
    with transaction.atomic():
        revoke_all_tokens(user, SessionEndReason.LOGOUT_ALL)
        record(AuditAction.LOGOUT_ALL, actor=user, organization=user.organization)


def change_password(user: User, *, current_password: str, new_password: str) -> None:
    if not user.check_password(current_password):
        raise ValidationError({"current_password": ["Current password is incorrect."]})
    _validate_password(new_password, user)
    with transaction.atomic():
        user.set_password(new_password)
        user.save(update_fields=["password", "updated_at"])
        revoke_all_tokens(user, SessionEndReason.PASSWORD_CHANGED)
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
def check_can_administer(actor: User, target: User) -> None:
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
    check_can_administer(actor, target)
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
    check_can_administer(actor, target)
    with transaction.atomic():
        target = _lock(target)
        if not target.is_active:
            return target
        if target.role == Role.ORG_ADMIN:
            _ensure_another_active_admin(target)
        target.is_active = False
        target.deactivated_at = timezone.now()
        target.save(update_fields=["is_active", "deactivated_at", "updated_at"])
        revoke_all_tokens(target, SessionEndReason.USER_DEACTIVATED)
        record(
            AuditAction.USER_DEACTIVATED,
            actor=actor,
            organization=target.organization,
            target=target,
        )
    return target


def sign_out_everywhere(*, actor: User, target: User) -> None:
    """An admin ends every session of a member (the account stays active)."""
    check_can_administer(actor, target)
    with transaction.atomic():
        target = _lock(target)
        revoke_all_tokens(target, SessionEndReason.REVOKED)
        record(
            AuditAction.USER_SESSIONS_REVOKED,
            actor=actor,
            organization=target.organization,
            target=target,
        )


def reactivate_user(*, actor: User, target: User) -> User:
    check_can_administer(actor, target)
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
        queue_invitation_email(invitation, raw_token)
    return invitation, raw_token


def queue_invitation_email(invitation: Invitation, raw_token: str) -> None:
    """Queue the email in the current transaction (ADR 0007), in the invitation's tenant.

    The task's argument is the token encrypted, never the token itself.
    """
    from apps.accounts.tasks import send_invitation_email  # noqa: PLC0415 - import cycle

    with rls.tenant_scope(invitation.organization_id):
        send_invitation_email.enqueue(str(invitation.pk), crypto.encrypt(raw_token))


def resend_invitation(*, actor: User, invitation: Invitation) -> tuple[Invitation, str]:
    """A new token (the old link stops working) and a new email."""
    require_permission(actor, Perm.INVITATION_MANAGE)
    require_same_tenant(actor, invitation)
    with transaction.atomic():
        invitation = Invitation.objects.select_for_update().get(pk=invitation.pk)
        if invitation.status != InvitationStatus.PENDING:
            raise ValidationError({"detail": "Only pending invitations can be resent."})
        raw_token = secrets.token_urlsafe(32)
        invitation.token_hash = hash_invitation_token(raw_token)
        invitation.email_status, invitation.email_last_error = EmailStatus.QUEUED, ""
        invitation.save(update_fields=["token_hash", "email_status", "email_last_error"])
        record(
            AuditAction.INVITATION_RESENT,
            actor=actor,
            organization=invitation.organization,
            target=invitation,
        )
        queue_invitation_email(invitation, raw_token)
    return invitation, raw_token


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
    token_hash = hash_invitation_token(raw_token)
    # Public endpoint: work in the invitation's tenant (nothing, for a bad token).
    with rls.scope(scope_for_invitation(token_hash)):
        return _accept_invitation(token_hash, password, full_name, invalid)


def _accept_invitation(
    token_hash: str, password: str, full_name: str, invalid: ValidationError
) -> User:
    with transaction.atomic():
        invitation = (
            Invitation.objects.select_for_update(of=("self",))
            .select_related("organization")
            .filter(token_hash=token_hash)
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
        try:
            with transaction.atomic():
                user.save()
        except IntegrityError as exc:
            # Another transaction registered this address after the check above.
            raise invalid from exc
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
