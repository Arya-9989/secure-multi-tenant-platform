from __future__ import annotations

from django.db.models import Count, Q
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import mixins, status
from rest_framework.request import Request
from rest_framework.response import Response

from apps.accounts.roles import ApiScope, Perm
from apps.common.views import TenantScopedViewSet
from apps.organizations import services
from apps.organizations.models import Organization
from apps.organizations.serializers import OrganizationSerializer


@extend_schema_view(
    list=extend_schema(summary="List organizations (only your own unless super admin)"),
    retrieve=extend_schema(summary="Retrieve an organization"),
)
@extend_schema(tags=["organizations"])
class OrganizationViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    TenantScopedViewSet[Organization],
):
    # Meta.ordering is ignored for GROUP BY queries, hence the explicit order_by.
    queryset = Organization.objects.annotate(
        member_count=Count("users", filter=Q(users__is_active=True))
    ).order_by("name")
    serializer_class = OrganizationSerializer
    filterset_fields = ("is_active",)
    search_fields = ("name", "slug")
    ordering_fields = ("name", "created_at")
    http_method_names = ("get", "post", "patch", "head", "options")
    required_permissions = {
        "list": Perm.ORGANIZATION_VIEW,
        "retrieve": Perm.ORGANIZATION_VIEW,
        "create": Perm.ORGANIZATION_MANAGE,
        "partial_update": Perm.ORGANIZATION_MANAGE,
    }
    api_key_scopes = {"list": ApiScope.ORGANIZATION_READ, "retrieve": ApiScope.ORGANIZATION_READ}

    @extend_schema(summary="Create an organization (super admin)")
    def create(self, request: Request) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        organization = services.create_organization(
            actor=self.actor,
            name=serializer.validated_data["name"],
            slug=serializer.validated_data.get("slug"),
            is_active=serializer.validated_data.get("is_active", True),
        )
        return Response(
            self.get_serializer(self.get_queryset().get(pk=organization.pk)).data,
            status=status.HTTP_201_CREATED,
        )

    @extend_schema(
        summary="Update an organization (super admin)",
        description="Setting `is_active=false` blocks every member from authenticating.",
    )
    def partial_update(self, request: Request, pk: str | None = None) -> Response:
        organization = self.get_object()
        serializer = self.get_serializer(organization, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        services.update_organization(
            actor=self.actor, organization=organization, changes=dict(serializer.validated_data)
        )
        return Response(self.get_serializer(self.get_queryset().get(pk=organization.pk)).data)
