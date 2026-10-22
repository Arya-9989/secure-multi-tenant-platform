from typing import Any

from django.contrib import admin
from django.http import HttpRequest

from apps.accounts.models import Invitation, User


@admin.register(User)
class UserAdmin(admin.ModelAdmin[User]):
    """Inspection only. Users join via invitations; super admins via ``createsuperuser``."""

    list_display = ("email", "full_name", "role", "organization", "is_active", "date_joined")
    list_filter = ("role", "is_active", "organization")
    search_fields = ("email", "full_name")
    ordering = ("email",)
    fields = (
        "id",
        "email",
        "full_name",
        "role",
        "organization",
        "is_active",
        "deactivated_at",
        "last_login",
        "date_joined",
    )
    readonly_fields = fields

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False


@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin[Invitation]):
    list_display = ("email", "organization", "role", "created_at", "expires_at", "accepted_at")
    list_filter = ("role", "organization")
    search_fields = ("email",)
    readonly_fields = tuple(f.name for f in Invitation._meta.fields)

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False
