from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import BaseThrottle, ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from apps.accounts import services
from apps.accounts.models import User, normalize_email
from apps.accounts.serializers.auth import (
    LoginSerializer,
    LogoutSerializer,
    PasswordChangeSerializer,
    RefreshSerializer,
    TokenPairResponseSerializer,
)
from apps.accounts.serializers.users import MeSerializer
from apps.auditlogs.models import AuditAction
from apps.auditlogs.services import record
from apps.common.tenancy import resolve_user


def _current_user(request: Request) -> User:
    user = resolve_user(request.user)
    if user is None:
        raise NotAuthenticated
    return user


class _AuthThrottled:
    # Brute-force protection: a strict per-client rate on credential endpoints.
    throttle_classes: Sequence[type[BaseThrottle]] = (ScopedRateThrottle,)
    throttle_scope = "auth"


class LoginView(_AuthThrottled, TokenObtainPairView):
    # TokenViewBase already disables authentication and permission checks.
    serializer_class = LoginSerializer

    @extend_schema(
        tags=["auth"],
        summary="Obtain an access/refresh token pair",
        description=(
            "Rate-limited per client (`THROTTLE_AUTH`). Every attempt is written to the audit "
            "log; failures use one generic message so accounts cannot be enumerated."
        ),
        responses={
            200: TokenPairResponseSerializer,
            401: OpenApiResponse(description="Invalid credentials (deliberately generic)."),
            429: OpenApiResponse(description="Too many attempts."),
        },
        auth=[],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = cast(LoginSerializer, self.get_serializer(data=request.data))
        try:
            serializer.is_valid(raise_exception=True)
        except AuthenticationFailed:
            _record_failed_login(request.data)
            raise
        user = cast(User, serializer.user)
        record(AuditAction.LOGIN_SUCCEEDED, actor=user, organization=user.organization)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)


def _record_failed_login(data: Any) -> None:
    email = normalize_email(str(data.get("email", "")))[:254] if isinstance(data, Mapping) else ""
    known = (
        User.objects.select_related("organization").filter(email=email).first() if email else None
    )
    # Attributed to the targeted account's tenant so its admins can see attacks
    # on their users; attempts against unknown emails are platform-level.
    record(
        AuditAction.LOGIN_FAILED,
        organization=known.organization if known else None,
        target=known,
        metadata={"email": email},
    )


class RefreshView(_AuthThrottled, TokenRefreshView):
    serializer_class = RefreshSerializer

    @extend_schema(
        tags=["auth"],
        summary="Rotate the refresh token",
        description=(
            "Returns a new access token **and a new refresh token**. The submitted refresh "
            "token is blacklisted and cannot be used again."
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
        description="Blacklists the given refresh token. It must belong to the caller.",
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
