"""Managing API keys: org admins issue, rotate and revoke their organization's keys."""

from __future__ import annotations

from typing import Any

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import mixins, serializers, status
from rest_framework.decorators import action
from rest_framework.request import Request
from rest_framework.response import Response

from apps.accounts.roles import ApiScope, Perm
from apps.apikeys import services
from apps.apikeys.models import KEY_PREFIX, ApiKey
from apps.common.serializers import StrictSerializer
from apps.common.tenancy import TenantScopedPrimaryKeyRelatedField, resolve_user
from apps.common.views import TenantScopedViewSet
from apps.organizations.models import Organization


class ApiKeySerializer(serializers.ModelSerializer[ApiKey]):
    prefix = serializers.SerializerMethodField(help_text="The public part, to recognise a key.")
    status = serializers.CharField(read_only=True)
    created_by = serializers.EmailField(source="created_by.email", read_only=True)
    scopes = serializers.ListField(child=serializers.ChoiceField(choices=list(ApiScope)))

    class Meta:
        model = ApiKey
        fields: tuple[str, ...] = (
            "id",
            "organization",
            "name",
            "prefix",
            "scopes",
            "status",
            "created_by",
            "created_at",
            "expires_at",
            "revoked_at",
            "last_used_at",
            "last_used_ip",
            "rotated_from",
        )
        read_only_fields: tuple[str, ...] = fields

    def get_prefix(self, key: ApiKey) -> str:
        return f"{KEY_PREFIX}_{key.prefix}"


class ApiKeyIssuedSerializer(ApiKeySerializer):
    key = serializers.CharField(read_only=True, help_text="Shown once. Only a hash is stored.")

    class Meta(ApiKeySerializer.Meta):
        fields = (*ApiKeySerializer.Meta.fields, "key")
        read_only_fields = fields


class ApiKeyCreateSerializer(StrictSerializer):
    name = serializers.CharField(max_length=100)
    scopes = serializers.MultipleChoiceField(choices=[s.value for s in ApiScope])
    expires_in_days = serializers.IntegerField(
        min_value=1, max_value=services.MAX_LIFETIME_DAYS, default=90
    )
    organization = TenantScopedPrimaryKeyRelatedField(
        queryset=Organization.objects.all(),
        required=False,
        help_text="Super admins only. Defaults to the caller's own organization.",
    )

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        if "organization" not in attrs:
            user = resolve_user(self.context["request"].user)
            if user is None or user.organization is None:
                raise serializers.ValidationError({"organization": ["This field is required."]})
            attrs["organization"] = user.organization
        attrs["scopes"] = sorted(attrs["scopes"])
        return attrs


class ApiKeyRotateSerializer(StrictSerializer):
    grace_minutes = serializers.IntegerField(
        min_value=0,
        max_value=services.MAX_GRACE_MINUTES,
        default=0,
        help_text="How long the old key keeps working (0: revoked at once).",
    )


@extend_schema_view(
    list=extend_schema(summary="List your organization's API keys"),
    retrieve=extend_schema(summary="Retrieve an API key (never its secret)"),
)
@extend_schema(tags=["api-keys"])
class ApiKeyViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    TenantScopedViewSet[ApiKey],
):
    queryset = ApiKey.objects.select_related("organization", "created_by")
    serializer_class = ApiKeySerializer
    http_method_names = ("get", "post", "head", "options")
    required_permissions = {
        "list": Perm.API_KEY_MANAGE,
        "retrieve": Perm.API_KEY_MANAGE,
        "create": Perm.API_KEY_MANAGE,
        "revoke": Perm.API_KEY_MANAGE,
        "rotate": Perm.API_KEY_MANAGE,
    }

    @extend_schema(
        summary="Issue an API key for a service",
        description=(
            "Read-only scopes, tenant-bound, expiring (at most 365 days). The full key is in "
            "this response **once**; only a SHA-256 hash of its secret is stored. Use it as "
            "`Authorization: ApiKey <key>`."
        ),
        request=ApiKeyCreateSerializer,
        responses={201: ApiKeyIssuedSerializer},
    )
    def create(self, request: Request) -> Response:
        serializer = ApiKeyCreateSerializer(
            data=request.data, context=self.get_serializer_context()
        )
        serializer.is_valid(raise_exception=True)
        key, full = services.create_key(actor=self.actor, **serializer.validated_data)
        return Response({**ApiKeySerializer(key).data, "key": full}, status=status.HTTP_201_CREATED)

    @extend_schema(summary="Revoke an API key at once", request=None, responses=ApiKeySerializer)
    @action(detail=True, methods=["post"])
    def revoke(self, request: Request, pk: str | None = None) -> Response:
        key = services.revoke_key(actor=self.actor, key=self.get_object())
        return Response(ApiKeySerializer(key).data)

    @extend_schema(
        summary="Rotate an API key",
        description=(
            "Issues a new key with the same name and scopes (shown once). The old key keeps "
            "working for `grace_minutes`, so a service can switch over without downtime."
        ),
        request=ApiKeyRotateSerializer,
        responses={201: ApiKeyIssuedSerializer},
    )
    @action(detail=True, methods=["post"])
    def rotate(self, request: Request, pk: str | None = None) -> Response:
        serializer = ApiKeyRotateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        key, full = services.rotate_key(
            actor=self.actor,
            key=self.get_object(),
            grace_minutes=serializer.validated_data["grace_minutes"],
        )
        return Response({**ApiKeySerializer(key).data, "key": full}, status=status.HTTP_201_CREATED)
