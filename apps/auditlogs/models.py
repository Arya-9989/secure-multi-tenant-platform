from __future__ import annotations

import uuid
from typing import Any, NoReturn

from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder
from django.db import models
from django.utils import timezone

from apps.common.tenancy import TenantQuerySet


class AuditAction(models.TextChoices):
    LOGIN_SUCCEEDED = "auth.login_succeeded", "Login succeeded"
    LOGIN_FAILED = "auth.login_failed", "Login failed"
    LOGOUT = "auth.logout", "Logout"
    LOGOUT_ALL = "auth.logout_all", "Logout from all sessions"
    PASSWORD_CHANGED = "auth.password_changed", "Password changed"
    ORGANIZATION_CREATED = "organization.created", "Organization created"
    ORGANIZATION_UPDATED = "organization.updated", "Organization updated"
    USER_PROFILE_UPDATED = "user.profile_updated", "User profile updated"
    USER_ROLE_CHANGED = "user.role_changed", "User role changed"
    USER_DEACTIVATED = "user.deactivated", "User deactivated"
    USER_REACTIVATED = "user.reactivated", "User reactivated"
    INVITATION_CREATED = "invitation.created", "Invitation created"
    INVITATION_REVOKED = "invitation.revoked", "Invitation revoked"
    INVITATION_ACCEPTED = "invitation.accepted", "Invitation accepted"


class AuditLogImmutableError(Exception):
    """Raised on any attempt to modify or delete an audit record."""


class AuditLogQuerySet(TenantQuerySet["AuditLog"]):
    def update(self, **kwargs: Any) -> NoReturn:
        raise AuditLogImmutableError("Audit log entries cannot be updated.")

    def delete(self) -> NoReturn:
        raise AuditLogImmutableError("Audit log entries cannot be deleted.")

    def bulk_update(self, *args: Any, **kwargs: Any) -> NoReturn:
        raise AuditLogImmutableError("Audit log entries cannot be updated.")


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

    objects = AuditLogQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at", "-id")
        indexes = (
            models.Index(fields=("organization", "-created_at")),
            models.Index(fields=("action", "-created_at")),
            models.Index(fields=("request_id",)),
        )

    def __str__(self) -> str:
        return f"{self.created_at:%Y-%m-%d %H:%M:%S} {self.action} by {self.actor_email or '-'}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            raise AuditLogImmutableError("Audit log entries cannot be updated.")
        kwargs["force_insert"] = True
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> NoReturn:
        raise AuditLogImmutableError("Audit log entries cannot be deleted.")

    @property
    def tenant_id(self) -> uuid.UUID | None:
        return self.organization_id
