"""Inspection-only: keys are issued by each organization's admins through the API."""

from django.contrib import admin

from apps.accounts.admin import ViewOnlyAdmin
from apps.apikeys.models import ApiKey


@admin.register(ApiKey)
class ApiKeyAdmin(ViewOnlyAdmin[ApiKey]):
    list_display = ("name", "prefix", "organization", "expires_at", "revoked_at", "last_used_at")
    list_filter = ("organization",)
    list_select_related = ("organization",)
    search_fields = ("name", "prefix")
    exclude = ("secret_hash",)  # a hash, but there is no reason to show even that
