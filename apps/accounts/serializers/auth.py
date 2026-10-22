from __future__ import annotations

from typing import Any

from django.db import transaction
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenRefreshSerializer,
)
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.utils import datetime_from_epoch

from apps.accounts.authentication import (
    TenantRefreshToken,
    token_matches_user,
    user_can_authenticate,
)
from apps.accounts.models import User
from apps.accounts.scopes import scope_for_account
from apps.common import rls
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
        user_id = refresh.get(api_settings.USER_ID_CLAIM)
        # The signature is valid, so the claim names the account to refresh for.
        rls.bind(scope_for_account(user_id=user_id))
        user = User.objects.select_related("organization").filter(pk=user_id).first()
        if user is None or not user_can_authenticate(user) or not token_matches_user(refresh, user):
            raise AuthenticationFailed(
                self.error_messages["no_active_account"], "no_active_account"
            )
        with transaction.atomic():
            # Claim the token by blacklisting it *before* minting a new pair. The
            # unique constraint makes the claim atomic: when two requests race
            # with the same token, exactly one creates the row and wins.
            # (SimpleJWT checks the blacklist first and writes it afterwards.)
            outstanding, _created = OutstandingToken.objects.get_or_create(
                jti=refresh[api_settings.JTI_CLAIM],
                defaults={
                    "user": user,
                    "token": str(refresh),
                    "created_at": refresh.current_time,
                    "expires_at": datetime_from_epoch(refresh["exp"]),
                },
            )
            _entry, claimed = BlacklistedToken.objects.get_or_create(token=outstanding)
            if not claimed:
                raise TokenError(_("Token is blacklisted"))
            data = {"access": str(refresh.access_token)}
            refresh.set_jti()
            refresh.set_exp()
            refresh.set_iat()
            refresh.outstand()
            data["refresh"] = str(refresh)
        return data


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
