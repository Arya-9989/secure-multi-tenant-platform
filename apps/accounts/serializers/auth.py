from __future__ import annotations

from typing import Any

from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenRefreshSerializer,
)
from rest_framework_simplejwt.settings import api_settings

from apps.accounts.authentication import (
    TenantRefreshToken,
    token_matches_user,
    user_can_authenticate,
)
from apps.accounts.models import User
from apps.common.serializers import StrictSerializer


class LoginSerializer(TokenObtainPairSerializer):
    token_class = TenantRefreshToken
    # One message for unknown email, wrong password, inactive user or inactive
    # organization, so the endpoint cannot be used to enumerate accounts.
    default_error_messages = {"no_active_account": _("Invalid email or password.")}


class RefreshSerializer(TokenRefreshSerializer):
    token_class = TenantRefreshToken
    default_error_messages = {"no_active_account": _("Session is no longer valid.")}

    def validate(self, attrs: dict[str, Any]) -> dict[str, str]:
        refresh = self.token_class(attrs["refresh"])
        user = (
            User.objects.select_related("organization")
            .filter(pk=refresh.get(api_settings.USER_ID_CLAIM))
            .first()
        )
        if user is None or not user_can_authenticate(user) or not token_matches_user(refresh, user):
            raise AuthenticationFailed(
                self.error_messages["no_active_account"], "no_active_account"
            )
        return super().validate(attrs)


class TokenPairResponseSerializer(serializers.Serializer[Any]):
    access = serializers.CharField()
    refresh = serializers.CharField()


class LogoutSerializer(StrictSerializer):
    refresh = serializers.CharField()


class PasswordChangeSerializer(StrictSerializer):
    current_password = serializers.CharField(
        style={"input_type": "password"}, trim_whitespace=False
    )
    new_password = serializers.CharField(style={"input_type": "password"}, trim_whitespace=False)
