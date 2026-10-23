from __future__ import annotations

from typing import Any

from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenObtainSerializer,
    TokenRefreshSerializer,
)
from rest_framework_simplejwt.settings import api_settings

from apps.accounts import sessions
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

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """Check the credentials only. The view decides what comes next: a second
        factor (ADR 0004) or the session itself (``apps.accounts.signin``)."""
        return TokenObtainSerializer.validate(self, attrs)


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
        try:
            successor = sessions.rotate(refresh, user)
        except sessions.InvalidSessionError as exc:
            # The same answer for a replayed, revoked, expired or unknown session.
            raise TokenError(_("Token is invalid")) from exc
        return {"access": str(successor.access_token), "refresh": str(successor)}


class TokenPairResponseSerializer(serializers.Serializer[Any]):
    access = serializers.CharField()
    refresh = serializers.CharField()


class LoginResultSerializer(serializers.Serializer[Any]):
    """Either the token pair, or (with MFA enabled) what the second step needs."""

    access = serializers.CharField(required=False, help_text="Without MFA.")
    refresh = serializers.CharField(required=False, help_text="Without MFA.")
    mfa_required = serializers.BooleanField(required=False, help_text="With MFA: true.")
    mfa_token = serializers.CharField(
        required=False, help_text="With MFA: send to /auth/mfa/verify/ within 5 minutes."
    )
    methods = serializers.ListField(
        child=serializers.ChoiceField(choices=["totp", "webauthn", "recovery_code"]),
        required=False,
        help_text="With MFA: the second factors this account can use.",
    )


class LogoutSerializer(StrictSerializer):
    refresh = serializers.CharField()


class PasswordChangeSerializer(StrictSerializer):
    current_password = serializers.CharField(
        style={"input_type": "password"}, trim_whitespace=False
    )
    new_password = serializers.CharField(style={"input_type": "password"}, trim_whitespace=False)
