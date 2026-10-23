"""Second factors (ADR 0004). Every row carries the user's organization so that
tenant scoping and row-level security apply as for any other tenant data."""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.common.tenancy import TenantQuerySet


class _UserOwned(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="+",
        help_text="The user's organization (row-level security); empty for super admins.",
    )
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        abstract = True

    @property
    def tenant_id(self) -> uuid.UUID | None:
        return self.organization_id


class TotpDevice(_UserOwned):
    """One authenticator app per user. Unconfirmed until a first valid code."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="totp_device"
    )
    secret_encrypted = models.TextField(editable=False, help_text="Fernet-encrypted seed.")
    confirmed_at = models.DateTimeField(null=True, blank=True)
    # Replay protection: the highest time step accepted so far.
    last_used_step = models.BigIntegerField(default=0, editable=False)

    objects = TenantQuerySet.as_manager()

    class Meta:
        verbose_name = "TOTP device"

    def __str__(self) -> str:
        return f"TOTP for {self.user_id}"


class WebAuthnCredential(_UserOwned):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="webauthn_credentials"
    )
    name = models.CharField(max_length=64)
    credential_id = models.CharField(max_length=1366, unique=True, help_text="base64url")
    public_key = models.BinaryField(editable=False)
    sign_count = models.BigIntegerField(default=0)
    transports = models.JSONField(default=list, blank=True)
    aaguid = models.CharField(max_length=36, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    objects = TenantQuerySet.as_manager()

    class Meta:
        verbose_name = "WebAuthn credential"
        ordering = ("created_at",)

    def __str__(self) -> str:
        return f"{self.name} ({self.user_id})"


class RecoveryCode(_UserOwned):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="recovery_codes"
    )
    code_hash = models.CharField(max_length=64, unique=True, editable=False)
    used_at = models.DateTimeField(null=True, blank=True)

    objects = TenantQuerySet.as_manager()

    class Meta:
        indexes = (models.Index(fields=("user", "used_at")),)

    def __str__(self) -> str:
        return f"recovery code of {self.user_id}"
