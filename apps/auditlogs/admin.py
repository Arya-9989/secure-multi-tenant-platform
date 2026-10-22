from typing import Any

from django.contrib import admin
from django.http import HttpRequest

from apps.auditlogs.models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin[AuditLog]):
    """Read-only: the audit log is append-only, even for superusers."""

    list_display = ("created_at", "action", "actor_email", "organization", "ip_address")
    list_filter = ("action", "organization")
    search_fields = ("actor_email", "target_id", "request_id")
    date_hierarchy = "created_at"

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False
