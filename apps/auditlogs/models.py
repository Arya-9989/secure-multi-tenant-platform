from __future__ import annotations

import uuid
from collections.abc import Collection, Iterable
from typing import Any, NoReturn

from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder
from django.db import models
from django.utils import timezone

from apps.common.tenancy import TenantQuerySet


class AuditAction(models.TextChoices):
    LOGIN_SUCCEEDED = "auth.login_succeeded", "Login succeeded"
    LOGIN_FAILED = "auth.login_failed", "Login failed"
    REFRESH_TOKEN_REUSE_DETECTED = (
        "auth.refresh_reuse_detected",
        "Refresh token replayed; session revoked",
    )
    MFA_FAILED = "auth.mfa_failed", "Second factor rejected"
    SSO_FAILED = "auth.sso_failed", "Single sign-on rejected"
    LOGOUT = "auth.logout", "Logout"
    LOGOUT_ALL = "auth.logout_all", "Logout from all sessions"
    PASSWORD_CHANGED = "auth.password_changed", "Password changed"
    ORGANIZATION_CREATED = "organization.created", "Organization created"
    ORGANIZATION_UPDATED = "organization.updated", "Organization updated"
    MFA_TOTP_ENABLED = "mfa.totp_enabled", "Authenticator app enabled"
    MFA_TOTP_DISABLED = "mfa.totp_disabled", "Authenticator app disabled"
    MFA_WEBAUTHN_ADDED = "mfa.webauthn_added", "Security key added"
    MFA_WEBAUTHN_REMOVED = "mfa.webauthn_removed", "Security key removed"
    MFA_RECOVERY_CODES_GENERATED = "mfa.recovery_codes_generated", "Recovery codes generated"
    MFA_RESET = "mfa.reset", "Second factors reset by an admin"
    API_KEY_CREATED = "api_key.created", "API key created"
    API_KEY_ROTATED = "api_key.rotated", "API key rotated"
    API_KEY_REVOKED = "api_key.revoked", "API key revoked"
    AUDIT_RETENTION_APPLIED = "audit.retention_applied", "Audit log retention applied"
    SSO_PROVIDER_CREATED = "sso.provider_created", "SSO provider configured"
    SSO_PROVIDER_UPDATED = "sso.provider_updated", "SSO provider updated"
    SSO_PROVIDER_DELETED = "sso.provider_deleted", "SSO provider removed"
    USER_PROFILE_UPDATED = "user.profile_updated", "User profile updated"
    USER_ROLE_CHANGED = "user.role_changed", "User role changed"
    USER_DEACTIVATED = "user.deactivated", "User deactivated"
    USER_REACTIVATED = "user.reactivated", "User reactivated"
    INVITATION_CREATED = "invitation.created", "Invitation created"
    INVITATION_REVOKED = "invitation.revoked", "Invitation revoked"
    INVITATION_RESENT = "invitation.resent", "Invitation resent with a new link"
    INVITATION_ACCEPTED = "invitation.accepted", "Invitation accepted"


class AuditLogImmutableError(Exception):
    """Raised on any attempt to modify or delete an audit record."""


UNCHAINED = "Audit events are appended with apps.auditlogs.services.record(), which chains them."


class AuditLogQuerySet(TenantQuerySet["AuditLog"]):
    def update(self, **kwargs: Any) -> NoReturn:
        raise AuditLogImmutableError("Audit log entries cannot be updated.")

    def delete(self) -> NoReturn:
        raise AuditLogImmutableError("Audit log entries cannot be deleted.")

    def bulk_update(self, *args: Any, **kwargs: Any) -> NoReturn:
        raise AuditLogImmutableError("Audit log entries cannot be updated.")

    def bulk_create(  # noqa: PLR0917 - the signature of QuerySet.bulk_create
        self,
        objs: Iterable[AuditLog],
        batch_size: int | None = None,
        ignore_conflicts: bool = False,
        update_conflicts: bool = False,
        update_fields: Collection[str] | None = None,
        unique_fields: Collection[str] | None = None,
    ) -> list[AuditLog]:
        # ``update_conflicts`` turns the insert into an upsert, i.e. an update.
        if update_conflicts:
            raise AuditLogImmutableError("Audit log entries cannot be updated.")
        # A bulk insert would skip the hash chain (ADR 0006): one at a time, by record().
        raise AuditLogImmutableError(UNCHAINED)


class AuditLog(models.Model):
    """Append-only record of a security-relevant event.

    Immutability is enforced at three levels: this model, its QuerySet, and
    (on PostgreSQL) a ``BEFORE UPDATE OR DELETE`` trigger installed by
    migration ``0002`` - so even raw SQL from the application role fails.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="+",
        help_text="Tenant the event belongs to; empty for platform-level events.",
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="+",
    )
    actor_email = models.EmailField(blank=True, help_text="Snapshot at the time of the event.")
    action = models.CharField(max_length=64, choices=AuditAction.choices)
    target_type = models.CharField(max_length=64, blank=True)
    target_id = models.CharField(max_length=64, blank=True)
    metadata = models.JSONField(default=dict, blank=True, encoder=DjangoJSONEncoder)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    request_id = models.CharField(max_length=64, blank=True)
    # Tamper evidence (ADR 0006): one hash chain per tenant (and one for the platform).
    chain_seq = models.BigIntegerField(default=0, editable=False)
    prev_hash = models.CharField(max_length=64, default="", editable=False)
    hash = models.CharField(max_length=64, default="", editable=False)

    objects = AuditLogQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at", "-id")
        indexes = (
            models.Index(fields=("organization", "-created_at")),
            models.Index(fields=("action", "-created_at")),
            models.Index(fields=("request_id",)),
            models.Index(fields=("organization", "-chain_seq"), name="auditlog_chain_head"),
        )

    def __str__(self) -> str:
        return f"{self.created_at:%Y-%m-%d %H:%M:%S} {self.action} by {self.actor_email or '-'}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            raise AuditLogImmutableError("Audit log entries cannot be updated.")
        if not self.hash or self.chain_seq < 1:
            raise AuditLogImmutableError(UNCHAINED)
        kwargs["force_insert"] = True
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> NoReturn:
        raise AuditLogImmutableError("Audit log entries cannot be deleted.")

    @property
    def tenant_id(self) -> uuid.UUID | None:
        return self.organization_id


class AuditChainCheckpoint(models.Model):
    """Where a chain resumes after retention dropped its oldest rows (ADR 0006).

    Append-only by convention: verification uses the latest checkpoint per chain,
    so a retention cut is distinguishable from a deletion.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="+",
        help_text="The chain's tenant; empty for the platform chain.",
    )
    chain_seq = models.BigIntegerField(help_text="The last sequence number that was dropped.")
    hash = models.CharField(max_length=64)
    last_created_at = models.DateTimeField()
    partition = models.CharField(max_length=63)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    objects = TenantQuerySet.as_manager()

    class Meta:
        ordering = ("-chain_seq",)
        indexes = (models.Index(fields=("organization", "-chain_seq")),)

    def __str__(self) -> str:
        return f"checkpoint {self.organization_id or 'platform'}@{self.chain_seq}"

    @property
    def tenant_id(self) -> uuid.UUID | None:
        return self.organization_id


class AuditExportCursor(models.Model):
    """The last sequence number of each chain delivered to the SIEM (ADR 0006)."""

    chain = models.CharField(max_length=36, primary_key=True)
    last_seq = models.BigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"{self.chain}@{self.last_seq}"
