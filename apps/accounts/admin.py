"""Inspection-only admin for accounts, invitations and JWT sessions.

People join through invitations and super admins through ``createsuperuser``,
so nothing here edits a user. SimpleJWT's own token admins are replaced: they
display stored refresh tokens verbatim (rotated ones are live credentials) and
let an operator delete blacklist entries, which silently un-revokes a session.
"""

from typing import Any

from django.contrib import admin
from django.contrib.auth.models import Group
from django.http import HttpRequest
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

from apps.accounts.models import Invitation, User


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


admin.site.unregister(OutstandingToken)
admin.site.unregister(BlacklistedToken)
# Django's groups and model permissions play no part here: authorization is the
# role matrix in apps/accounts/roles.py. Hiding them avoids implying otherwise.
admin.site.unregister(Group)


@admin.register(OutstandingToken)
class OutstandingTokenAdmin(ViewOnlyAdmin[OutstandingToken]):
    list_display = ("jti", "user", "created_at", "expires_at")
    list_select_related = ("user",)
    search_fields = ("jti", "user__email")
    fields = ("jti", "user", "created_at", "expires_at")  # never the token itself
    ordering = ("-created_at",)


@admin.register(BlacklistedToken)
class BlacklistedTokenAdmin(ViewOnlyAdmin[BlacklistedToken]):
    list_display = ("token", "blacklisted_at")
    list_select_related = ("token__user",)
    search_fields = ("token__jti", "token__user__email")
    fields = ("token", "blacklisted_at")
    ordering = ("-blacklisted_at",)
