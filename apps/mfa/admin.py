"""Inspection-only: which users have which factors. Never a secret, seed or key."""

from django.contrib import admin

from apps.accounts.admin import ViewOnlyAdmin
from apps.mfa.models import RecoveryCode, TotpDevice, WebAuthnCredential


@admin.register(TotpDevice)
class TotpDeviceAdmin(ViewOnlyAdmin[TotpDevice]):
    list_display = ("user", "organization", "confirmed_at", "created_at")
    list_select_related = ("user", "organization")
    search_fields = ("user__email",)
    fields = ("id", "user", "organization", "confirmed_at", "created_at")


@admin.register(WebAuthnCredential)
class WebAuthnCredentialAdmin(ViewOnlyAdmin[WebAuthnCredential]):
    list_display = ("name", "user", "organization", "created_at", "last_used_at")
    list_select_related = ("user", "organization")
    search_fields = ("user__email", "name")
    fields = ("id", "name", "user", "organization", "aaguid", "sign_count", "created_at")


@admin.register(RecoveryCode)
class RecoveryCodeAdmin(ViewOnlyAdmin[RecoveryCode]):
    list_display = ("user", "organization", "used_at", "created_at")
    list_select_related = ("user", "organization")
    search_fields = ("user__email",)
    fields = ("id", "user", "organization", "used_at", "created_at")
