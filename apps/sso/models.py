"""Per-organization OpenID Connect providers and the identities they vouch for (ADR 0004)."""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.common.tenancy import TenantQuerySet


class OidcProvider(models.Model):
    """An organization's identity provider, configured by its admins."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.OneToOneField(
        "organizations.Organization", on_delete=models.PROTECT, related_name="sso_provider"
    )
    # Not a URLField: Django's URL validator wants a dotted host, and an IdP on a
    # private network (http://keycloak:8080) has none. Validated by the API instead.
    issuer = models.CharField(max_length=255, help_text="Exactly as the IdP reports it.")
    client_id = models.CharField(max_length=255)
    client_secret_encrypted = models.TextField(editable=False)
    allowed_domains = models.JSONField(
        default=list, blank=True, help_text="Email domains it may vouch for; empty: any."
    )
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    objects = TenantQuerySet.as_manager()

    class Meta:
        verbose_name = "OIDC provider"
        ordering = ("created_at",)

    def __str__(self) -> str:
        return f"{self.issuer} for {self.organization_id}"

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.organization_id


class SsoIdentity(models.Model):
    """A user linked to the IdP's stable subject, after their first SSO sign-in."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.PROTECT, related_name="+"
    )
    provider = models.ForeignKey(OidcProvider, on_delete=models.CASCADE, related_name="identities")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sso_identities"
    )
    subject = models.CharField(max_length=255)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    last_used_at = models.DateTimeField(null=True, blank=True)

    objects = TenantQuerySet.as_manager()

    class Meta:
        verbose_name = "SSO identity"
        verbose_name_plural = "SSO identities"
        constraints = (
            models.UniqueConstraint(fields=("provider", "subject"), name="sso_subject_once"),
            models.UniqueConstraint(fields=("provider", "user"), name="sso_one_identity_per_user"),
        )

    def __str__(self) -> str:
        return f"{self.subject} -> {self.user_id}"

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.organization_id
