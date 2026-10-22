"""JWT authentication hardened for multi-tenancy.

On top of SimpleJWT's signature/expiry/blacklist checks, every request
re-validates against the database:

* the user still exists and is active (soft deactivation is immediate),
* the user's organization is still active,
* the token's ``ver`` claim matches ``User.token_version`` - bumping the
  version (logout-all, password change, deactivation) revokes every access
  *and* refresh token issued before, without waiting for expiry.

Authorization never trusts claims for role or tenant: those are read from
the database row on each request.
"""

from __future__ import annotations

from typing import Any

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken, Token

from apps.accounts.models import User

TOKEN_VERSION_CLAIM = "ver"  # noqa: S105 - a claim name, not a secret


def user_can_authenticate(user: Any) -> bool:
    """SimpleJWT ``USER_AUTHENTICATION_RULE``: used at login and on refresh."""
    if not isinstance(user, User) or not user.is_active:
        return False
    if user.is_super_admin:
        return user.organization_id is None
    return user.organization is not None and user.organization.is_active


def token_matches_user(token: Token | dict[str, Any], user: User) -> bool:
    return token.get(TOKEN_VERSION_CLAIM) == user.token_version


class TenantRefreshToken(RefreshToken):
    """Refresh token carrying the user's token version (copied to access tokens)."""

    @classmethod
    def for_user(cls, user: Any) -> TenantRefreshToken:
        token = super().for_user(user)
        token[TOKEN_VERSION_CLAIM] = user.token_version
        return token  # type: ignore[return-value]


class TenantJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token: Token) -> User:  # type: ignore[override]
        user_id = validated_token.get(api_settings.USER_ID_CLAIM)
        if user_id is None:
            raise InvalidToken("Token contained no recognizable user identification")
        try:
            user: User = User.objects.select_related("organization").get(pk=user_id)
        except (User.DoesNotExist, ValidationError) as exc:
            raise AuthenticationFailed(_("User not found"), code="user_not_found") from exc
        if not user_can_authenticate(user):
            raise AuthenticationFailed(_("User is inactive"), code="user_inactive")
        if not token_matches_user(validated_token, user):
            raise AuthenticationFailed(_("Token has been revoked"), code="token_revoked")
        return user
