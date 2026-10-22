"""Inspection-only: providers are managed by each organization's admins through the API."""

from django.contrib import admin

from apps.accounts.admin import ViewOnlyAdmin
from apps.sso.models import OidcProvider, SsoIdentity


@admin.register(OidcProvider)
class OidcProviderAdmin(ViewOnlyAdmin[OidcProvider]):
    list_display = ("organization", "issuer", "client_id", "enabled", "updated_at")
    list_select_related = ("organization",)
    search_fields = ("issuer", "client_id", "organization__name")
    # Never the client secret, not even encrypted.
    fields = (
        "id",
        "organization",
        "issuer",
        "client_id",
        "allowed_domains",
        "enabled",
        "created_at",
    )


@admin.register(SsoIdentity)
class SsoIdentityAdmin(ViewOnlyAdmin[SsoIdentity]):
    list_display = ("user", "provider", "subject", "last_used_at")
    list_select_related = ("user", "provider")
    search_fields = ("user__email", "subject")
    fields = ("id", "user", "organization", "provider", "subject", "created_at", "last_used_at")
