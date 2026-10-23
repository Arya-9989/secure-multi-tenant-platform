from __future__ import annotations

import django_filters
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import mixins, serializers

from apps.accounts.roles import ApiScope, Perm
from apps.auditlogs.models import AuditAction, AuditLog
from apps.common.pagination import CreatedAtCursorPagination
from apps.common.views import TenantScopedViewSet


class AuditLogSerializer(serializers.ModelSerializer[AuditLog]):
    class Meta:
        model = AuditLog
        fields = (
            "id",
            "created_at",
            "organization",
            "actor",
            "actor_email",
            "action",
            "target_type",
            "target_id",
            "metadata",
            "ip_address",
            "user_agent",
            "request_id",
        )
        read_only_fields = fields


class AuditLogFilter(django_filters.FilterSet):
    action = django_filters.MultipleChoiceFilter(choices=AuditAction.choices)
    actor = django_filters.UUIDFilter(field_name="actor_id")
    organization = django_filters.UUIDFilter(field_name="organization_id")
    target_type = django_filters.CharFilter()
    target_id = django_filters.CharFilter()
    request_id = django_filters.CharFilter()
    ip_address = django_filters.CharFilter()
    created_after = django_filters.IsoDateTimeFilter(field_name="created_at", lookup_expr="gte")
    created_before = django_filters.IsoDateTimeFilter(field_name="created_at", lookup_expr="lt")

    class Meta:
        model = AuditLog
        fields = ("action", "actor", "organization", "target_type", "target_id", "request_id")


@extend_schema_view(
    list=extend_schema(
        summary="Query the audit log",
        description=(
            "Newest first, cursor-paginated. Org admins see their organization's events; "
            "super admins see everything, including platform-level events."
        ),
    ),
    retrieve=extend_schema(summary="Retrieve an audit event"),
)
@extend_schema(tags=["audit-logs"])
class AuditLogViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    TenantScopedViewSet[AuditLog],
):
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    pagination_class = CreatedAtCursorPagination
    filter_backends = (DjangoFilterBackend,)
    filterset_class = AuditLogFilter
    required_permissions = {"list": Perm.AUDIT_VIEW, "retrieve": Perm.AUDIT_VIEW}
    api_key_scopes = {"list": ApiScope.AUDIT_READ, "retrieve": ApiScope.AUDIT_READ}
