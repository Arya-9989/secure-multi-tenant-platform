from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

from drf_spectacular.utils import OpenApiResponse, PolymorphicProxySerializer, extend_schema
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated, Throttled
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import BaseThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from apps.accounts import login_throttle, services, signin
from apps.accounts.models import User
from apps.accounts.serializers.auth import (
    LoginSerializer,
    LogoutSerializer,
    MfaRequiredResponseSerializer,
    PasswordChangeSerializer,
    RefreshSerializer,
    TokenPairResponseSerializer,
)
from apps.accounts.serializers.users import MeSerializer
from apps.common.tenancy import resolve_user
from apps.common.throttling import ClientScopedRateThrottle
from apps.mfa import services as mfa


def _current_user(request: Request) -> User:
    user = resolve_user(request.user)
    if user is None:
        raise NotAuthenticated
    return user


class _AuthThrottled:
    # Brute-force protection: a strict per-client rate on credential endpoints.
    throttle_classes: Sequence[type[BaseThrottle]] = (ClientScopedRateThrottle,)
    throttle_scope = "auth"


class LoginView(_AuthThrottled, TokenObtainPairView):
    # TokenViewBase already disables authentication and permission checks.
    serializer_class = LoginSerializer

    @extend_schema(
        tags=["auth"],
        summary="Obtain an access/refresh token pair",
        description=(
            "Rate-limited per client (`THROTTLE_AUTH`) and per account: after "
            "`LOGIN_ACCOUNT_FREE_ATTEMPTS` attempts, each further one waits for a doubling "
            "delay (capped at `LOGIN_ACCOUNT_MAX_DELAY_SECONDS`). A browser that signed in "
            "to the account before carries a `login_device` cookie and is counted on its own, "
            "so nobody can keep you out of your own devices. Every attempt is audited; "
            "failures use one generic message and unknown emails behave exactly like real "
            "ones, so accounts cannot be enumerated."
        ),
        responses={
            200: PolymorphicProxySerializer(
                component_name="LoginResult",
                serializers=[TokenPairResponseSerializer, MfaRequiredResponseSerializer],
                resource_type_field_name=None,
            ),
            401: OpenApiResponse(description="Invalid credentials (deliberately generic)."),
            429: OpenApiResponse(description="Too many attempts (see `Retry-After`)."),
        },
        auth=[],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        email = _email_of(request.data)
        decision = login_throttle.check(email, login_throttle.device_token_from(request))
        if not decision.allowed:
            raise Throttled(wait=decision.retry_after)
        serializer = cast(LoginSerializer, self.get_serializer(data=request.data))
        try:
            serializer.is_valid(raise_exception=True)
        except AuthenticationFailed:
            services.record_failed_login(email, delay=decision.delay)
            raise
        user = cast(User, serializer.user)
        if mfa.has_mfa(user):
            # The password was right, but the throttle bucket stays: guessing the
            # second factor counts against it too (ADR 0004).
            return Response(
                {
                    "mfa_required": True,
                    "mfa_token": mfa.issue_challenge(user),
                    "methods": mfa.methods(user),
                }
            )
        return signin.complete(request, user, decision=decision)


def _email_of(data: Any) -> str:
    value = data.get("email", "") if isinstance(data, Mapping) else ""
    return value if isinstance(value, str) else ""


class RefreshView(_AuthThrottled, TokenRefreshView):
    serializer_class = RefreshSerializer

    @extend_schema(
        tags=["auth"],
        summary="Rotate the refresh token",
        description=(
            "Returns a new access token **and a new refresh token**. The submitted refresh "
            "token can never be used again: presenting a rotated token is treated as theft, "
            "ends the whole session (every token from that sign-in) and is audited. Serialise "
            "refreshes in clients; two concurrent refreshes with one token end the session."
        ),
        responses={200: TokenPairResponseSerializer},
        auth=[],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return super().post(request, *args, **kwargs)


class LogoutView(GenericAPIView[Any]):
    serializer_class = LogoutSerializer
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        tags=["auth"],
        summary="Log out this session",
        description=(
            "Ends the session the refresh token belongs to, including its access tokens. "
            "The token must belong to the caller."
        ),
        responses={204: None},
    )
    def post(self, request: Request) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        services.logout(_current_user(request), serializer.validated_data["refresh"])
        return Response(status=status.HTTP_204_NO_CONTENT)


class LogoutAllView(APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        tags=["auth"],
        summary="Log out everywhere",
        description="Immediately revokes every access and refresh token issued to the caller.",
        request=None,
        responses={204: None},
    )
    def post(self, request: Request) -> Response:
        services.logout_everywhere(_current_user(request))
        return Response(status=status.HTTP_204_NO_CONTENT)


class MeView(GenericAPIView[User]):
    serializer_class = MeSerializer
    permission_classes = (IsAuthenticated,)

    @extend_schema(tags=["auth"], summary="Get own profile")
    def get(self, request: Request) -> Response:
        return Response(self.get_serializer(_current_user(request)).data)

    @extend_schema(tags=["auth"], summary="Update own profile")
    def patch(self, request: Request) -> Response:
        user = _current_user(request)
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        services.update_profile(user, changes=dict(serializer.validated_data))
        return Response(self.get_serializer(user).data)


class PasswordChangeView(_AuthThrottled, GenericAPIView[Any]):
    serializer_class = PasswordChangeSerializer
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        tags=["auth"],
        summary="Change own password",
        description="Validates the new password, then revokes all existing tokens.",
        responses={204: None},
    )
    def post(self, request: Request) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        services.change_password(
            _current_user(request),
            current_password=serializer.validated_data["current_password"],
            new_password=serializer.validated_data["new_password"],
        )
        return Response(status=status.HTTP_204_NO_CONTENT)
