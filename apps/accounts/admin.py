"""Inspection-only admin for accounts, invitations and sessions.

People join through invitations and super admins through ``createsuperuser``,
so nothing here edits a user. Sessions (refresh-token families, ADR 0002) are
listed without the ID of their redeemable token, and cannot be edited or
deleted: un-revoking a session would revive a session someone ended.
"""

from typing import Any

from django.contrib import admin
from django.contrib.auth.models import Group
from django.http import HttpRequest

from apps.accounts.models import Invitation, RefreshTokenFamily, User


class ViewOnlyAdmin[M: Any](admin.ModelAdmin[M]):
    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False


@admin.register(User)
class UserAdmin(ViewOnlyAdmin[User]):
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


@admin.register(Invitation)
class InvitationAdmin(ViewOnlyAdmin[Invitation]):
    list_display = ("email", "organization", "role", "created_at", "expires_at", "accepted_at")
    list_filter = ("role", "organization")
    search_fields = ("email",)
    # token_hash is a SHA-256 digest; there is no reason to show even that.
    exclude = ("token_hash",)


# Django's groups and model permissions play no part here: authorization is the
# role matrix in apps/accounts/roles.py. Hiding them avoids implying otherwise.
admin.site.unregister(Group)


@admin.register(RefreshTokenFamily)
class SessionAdmin(ViewOnlyAdmin[RefreshTokenFamily]):
    list_display = (
        "user",
        "organization",
        "created_at",
        "last_refreshed_at",
        "generation",
        "expires_at",
        "revoked_at",
        "revoked_reason",
    )
    list_filter = ("revoked_reason", "organization")
    list_select_related = ("user", "organization")
    search_fields = ("user__email", "ip_address")
    # Not the current token's ID: nobody needs it, so it is not shown.
    fields = (
        "id",
        "user",
        "organization",
        "generation",
        "created_at",
        "last_refreshed_at",
        "expires_at",
        "revoked_at",
        "revoked_reason",
        "ip_address",
        "user_agent",
    )
    ordering = ("-created_at",)
