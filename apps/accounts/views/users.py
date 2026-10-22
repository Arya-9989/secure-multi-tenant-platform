from __future__ import annotations

import django_filters
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import mixins, status
from rest_framework.decorators import action
from rest_framework.request import Request
from rest_framework.response import Response

from apps.accounts import services
from apps.accounts.models import User
from apps.accounts.roles import ApiScope, Perm, Role
from apps.accounts.serializers.users import UserRoleUpdateSerializer, UserSerializer
from apps.common.views import TenantScopedViewSet
from apps.mfa import services as mfa


class UserFilter(django_filters.FilterSet):
    role = django_filters.ChoiceFilter(choices=Role.choices)
    is_active = django_filters.BooleanFilter()
    organization = django_filters.UUIDFilter(field_name="organization_id")

    class Meta:
        model = User
        fields = ("role", "is_active", "organization")


@extend_schema_view(
    list=extend_schema(summary="List users in your organization (all users for super admins)"),
    retrieve=extend_schema(summary="Retrieve a user"),
)
@extend_schema(tags=["users"])
class UserViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    TenantScopedViewSet[User],
):
    """Tenant-scoped user directory. Users are created through invitations only."""

    queryset = User.objects.select_related("organization")
    serializer_class = UserSerializer
    filterset_class = UserFilter
    search_fields = ("email", "full_name")
    ordering_fields = ("email", "full_name", "date_joined", "role")
    http_method_names = ("get", "post", "patch", "head", "options")
    required_permissions = {
        "list": Perm.USER_VIEW,
        "retrieve": Perm.USER_VIEW,
        "partial_update": Perm.USER_MANAGE,
        "deactivate": Perm.USER_MANAGE,
        "reactivate": Perm.USER_MANAGE,
        "reset_mfa": Perm.USER_MANAGE,
    }
    api_key_scopes = {"list": ApiScope.USERS_READ, "retrieve": ApiScope.USERS_READ}

    @extend_schema(
        summary="Change a user's role",
        description=(
            "Only `ORG_ADMIN` and `MEMBER` are assignable. You cannot change your own role, "
            "super admin accounts, or demote an organization's last active admin. "
            "Any other field (e.g. `organization`, `is_staff`) is rejected with 400."
        ),
        request=UserRoleUpdateSerializer,
        responses=UserSerializer,
    )
    def partial_update(self, request: Request, pk: str | None = None) -> Response:
        target = self.get_object()
        serializer = UserRoleUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        updated = services.change_role(
            actor=self.actor, target=target, new_role=serializer.validated_data["role"]
        )
        return Response(UserSerializer(updated).data)

    @extend_schema(
        summary="Deactivate a user (soft)",
        description="Blocks login and revokes all of the user's tokens immediately.",
        request=None,
        responses=UserSerializer,
    )
    @action(detail=True, methods=["post"])
    def deactivate(self, request: Request, pk: str | None = None) -> Response:
        user = services.deactivate_user(actor=self.actor, target=self.get_object())
        return Response(UserSerializer(user).data)

    @extend_schema(
        summary="Reset a user's second factors",
        description=(
            "For a member who lost their authenticator: removes their authenticator app, "
            "security keys and recovery codes, and ends their sessions. Audited."
        ),
        request=None,
        responses={204: None},
    )
    @action(detail=True, methods=["post"], url_path="reset-mfa")
    def reset_mfa(self, request: Request, pk: str | None = None) -> Response:
        mfa.reset(actor=self.actor, target=self.get_object())
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(summary="Reactivate a user", request=None, responses=UserSerializer)
    @action(detail=True, methods=["post"])
    def reactivate(self, request: Request, pk: str | None = None) -> Response:
        user = services.reactivate_user(actor=self.actor, target=self.get_object())
        return Response(UserSerializer(user).data)
