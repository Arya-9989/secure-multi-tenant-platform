"""Tenant-bound, scoped, expiring API keys for services (ADR 0005)."""

from __future__ import annotations

import hashlib
import uuid

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone

from apps.common.tenancy import TenantQuerySet

KEY_PREFIX = "mtk"


def hash_secret(secret: str) -> str:
    """256 random bits need no slow hash: SHA-256 is preimage-resistant enough."""
    return hashlib.sha256(secret.encode()).hexdigest()


class ApiKeyQuerySet(TenantQuerySet["ApiKey"]):
    def usable(self) -> ApiKeyQuerySet:
        return self.filter(revoked_at__isnull=True, expires_at__gt=timezone.now())


class ApiKey(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.PROTECT, related_name="api_keys"
    )
    name = models.CharField(max_length=100)
    prefix = models.CharField(max_length=16, unique=True, editable=False)
    secret_hash = models.CharField(max_length=64, editable=False)
    scopes = models.JSONField(default=list)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+"
    )
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True, related_name="+"
    )
    rotated_from = models.OneToOneField(
        "self", on_delete=models.PROTECT, null=True, blank=True, related_name="rotated_to"
    )
    last_used_at = models.DateTimeField(null=True, blank=True)
    last_used_ip = models.GenericIPAddressField(null=True, blank=True)

    objects = ApiKeyQuerySet.as_manager()

    class Meta:
        verbose_name = "API key"
        ordering = ("-created_at",)
        constraints = (
            models.CheckConstraint(
                condition=Q(revoked_at__isnull=True) | Q(revoked_by__isnull=False),
                name="api_key_revocation_has_an_actor",
            ),
        )

    def __str__(self) -> str:
        return f"{self.name} ({KEY_PREFIX}_{self.prefix})"

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.organization_id

    @property
    def status(self) -> str:
        if self.revoked_at is not None:
            return "revoked"
        if self.expires_at <= timezone.now():
            return "expired"
        return "active"
