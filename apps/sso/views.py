"""SSO endpoints: provider configuration (org admins) and the sign-in redirect flow."""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlencode, urlsplit

from django.conf import settings
from django.http import HttpResponseRedirect
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
)
from rest_framework import mixins, serializers, status
from rest_framework.exceptions import AuthenticationFailed, NotFound
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.views import APIView

from apps.accounts import signin
from apps.accounts.authentication import user_can_authenticate
from apps.accounts.models import User
from apps.accounts.roles import Perm
from apps.accounts.scopes import scope_for_account
from apps.accounts.serializers.auth import TokenPairResponseSerializer
from apps.common import rls
from apps.common.serializers import StrictModelSerializer, StrictSerializer
from apps.common.tenancy import TenantScopedPrimaryKeyRelatedField, resolve_user
from apps.common.throttling import ClientScopedRateThrottle
from apps.common.views import TenantScopedViewSet
from apps.organizations.models import Organization
from apps.sso import oidc, services
from apps.sso.models import OidcProvider

logger = logging.getLogger(__name__)

_DOMAIN = re.compile(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")


class OidcProviderSerializer(StrictModelSerializer):
    organization = TenantScopedPrimaryKeyRelatedField(
        queryset=Organization.objects.all(),
        required=False,
        help_text="Super admins only. Defaults to the caller's own organization.",
    )
    client_secret = serializers.CharField(
        write_only=True, max_length=512, help_text="Stored encrypted; never returned."
    )
    allowed_domains = serializers.ListField(
        child=serializers.CharField(max_length=253), required=False, max_length=20
    )
    login_url = serializers.SerializerMethodField(help_text="Where members start signing in.")

    class Meta:
        model = OidcProvider
        fields = (
            "id",
            "organization",
            "issuer",
            "client_id",
            "client_secret",
            "allowed_domains",
            "enabled",
            "login_url",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "login_url", "created_at", "updated_at")

    def get_login_url(self, provider: OidcProvider) -> str:
        return reverse(
            "sso-login",
            args=[provider.organization.slug],
            request=self.context.get("request"),
        )

    def validate_issuer(self, value: str) -> str:
        parts = urlsplit(value)
        if not parts.netloc or parts.query or parts.fragment or parts.username:
            raise serializers.ValidationError("Enter the issuer URL exactly as the IdP reports it.")
        try:
            oidc.check_url(value)
        except oidc.SsoError as exc:
            raise serializers.ValidationError("The issuer must be an https:// URL.") from exc
        return value

    def validate_allowed_domains(self, value: list[str]) -> list[str]:
        domains = sorted({domain.strip().lower() for domain in value})
        invalid = [domain for domain in domains if not _DOMAIN.fullmatch(domain)]
        if invalid:
            raise serializers.ValidationError(f"Not a domain name: {', '.join(invalid)}.")
        return domains

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        if self.instance is None:
            if "client_secret" not in attrs:
                raise serializers.ValidationError({"client_secret": ["This field is required."]})
            if "organization" not in attrs:
                user = resolve_user(self.context["request"].user)
                if user is None or user.organization is None:
                    raise serializers.ValidationError({"organization": ["This field is required."]})
                attrs["organization"] = user.organization
        elif "organization" in attrs:
            raise serializers.ValidationError({"organization": ["This field cannot be changed."]})
        return attrs


@extend_schema_view(
    list=extend_schema(summary="List SSO providers (yours, or all for super admins)"),
    retrieve=extend_schema(summary="Retrieve an SSO provider"),
    create=extend_schema(summary="Configure your organization's OpenID Connect provider"),
    partial_update=extend_schema(summary="Update an SSO provider"),
    destroy=extend_schema(summary="Remove an SSO provider"),
)
@extend_schema(tags=["sso"])
class OidcProviderViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    TenantScopedViewSet[OidcProvider],
):
    queryset = OidcProvider.objects.select_related("organization")
    serializer_class = OidcProviderSerializer
    filterset_fields = ("enabled",)
    http_method_names = ("get", "post", "patch", "delete", "head", "options")
    required_permissions = {
        "list": Perm.SSO_MANAGE,
        "retrieve": Perm.SSO_MANAGE,
        "create": Perm.SSO_MANAGE,
        "partial_update": Perm.SSO_MANAGE,
        "destroy": Perm.SSO_MANAGE,
    }

    def create(self, request: Request) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        provider = services.create_provider(actor=self.actor, **serializer.validated_data)
        return Response(self.get_serializer(provider).data, status=status.HTTP_201_CREATED)

    def partial_update(self, request: Request, pk: str | None = None) -> Response:
        provider = self.get_object()
        serializer = self.get_serializer(provider, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        provider = services.update_provider(
            actor=self.actor, provider=provider, changes=dict(serializer.validated_data)
        )
        return Response(self.get_serializer(provider).data)

    def destroy(self, request: Request, pk: str | None = None) -> Response:
        services.delete_provider(actor=self.actor, provider=self.get_object())
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------- the sign-in flow
class _Public(APIView):
    authentication_classes = ()
    permission_classes = (AllowAny,)
    throttle_classes = (ClientScopedRateThrottle,)
    throttle_scope = "auth"


def _to_frontend(**params: str) -> HttpResponseRedirect:
    base: str = settings.FRONTEND_SSO_URL
    separator = "&" if "?" in base else "?"
    return HttpResponseRedirect(f"{base}{separator}{urlencode(params)}")


class SsoLoginView(_Public):
    @extend_schema(
        tags=["sso"],
        summary="Start signing in with your organization's identity provider",
        description=(
            "Redirects to the IdP (authorization code flow with PKCE, state and nonce). "
            "An unknown organization and one without SSO answer the same 404."
        ),
        responses={302: OpenApiResponse(description="To the IdP."), 404: None},
        auth=[],
    )
    def get(self, request: Request, slug: str) -> HttpResponseRedirect:
        provider = services.provider_for_slug(slug)
        if provider is None:
            raise NotFound
        try:
            return HttpResponseRedirect(services.login_url(provider))
        except oidc.SsoError as exc:
            services.record_failure(exc.reason, provider)
            return _to_frontend(error="sso_unavailable")


class SsoCallbackView(_Public):
    @extend_schema(
        tags=["sso"],
        summary="Where the IdP sends the browser back",
        description=(
            "Redirects to `FRONTEND_SSO_URL` with a one-time `code` (exchange it at "
            "`POST /auth/sso/exchange/`) or with `error=sso_failed`. The reason is audited."
        ),
        parameters=[
            OpenApiParameter("code", str),
            OpenApiParameter("state", str),
            OpenApiParameter("error", str),
        ],
        responses={302: OpenApiResponse(description="To the frontend.")},
        auth=[],
    )
    def get(self, request: Request) -> HttpResponseRedirect:
        state = str(request.query_params.get("state", ""))[:256]
        code = str(request.query_params.get("code", ""))[:2048]
        try:
            if request.query_params.get("error") or not code:
                # The IdP refused (or the user cancelled): still burn the state.
                oidc.consume_state(state)
                raise oidc.SsoError("idp_refused")
            user = services.complete(state=state, code=code)
        except oidc.SsoError as exc:
            logger.info("SSO sign-in failed: %s", exc.reason)
            services.record_failure(exc.reason, exc.provider)
            return _to_frontend(error="sso_failed")
        return _to_frontend(code=oidc.hand_off(str(user.pk)))


class SsoExchangeSerializer(StrictSerializer):
    code = serializers.CharField(max_length=128)


class SsoExchangeView(_Public):
    def get_authenticate_header(self, request: Request) -> str:
        return 'Bearer realm="api"'  # so a refusal is 401, as at /auth/login/

    @extend_schema(
        tags=["sso"],
        summary="Exchange the one-time SSO code for a token pair",
        request=SsoExchangeSerializer,
        responses={200: TokenPairResponseSerializer, 401: OpenApiResponse(description="Invalid.")},
        auth=[],
    )
    def post(self, request: Request) -> Response:
        serializer = SsoExchangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_id = oidc.redeem_hand_off(serializer.validated_data["code"])
        invalid = AuthenticationFailed("This sign-in code is invalid or has expired.")
        if user_id is None:
            raise invalid
        rls.bind(scope_for_account(user_id=user_id))
        user = User.objects.select_related("organization").filter(pk=user_id).first()
        if user is None or not user_can_authenticate(user):
            raise invalid
        return signin.complete(request, user, metadata={"channel": "sso"})
