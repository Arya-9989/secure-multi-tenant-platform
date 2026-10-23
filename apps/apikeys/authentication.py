"""``Authorization: ApiKey mtk_<prefix>_<secret>`` for services (ADR 0005)."""

from __future__ import annotations

from typing import Any

from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

from apps.apikeys import services
from apps.common import rls

KEYWORD = b"apikey"
INVALID = "Invalid API key."


class ApiKeyAuthentication(BaseAuthentication):
    def authenticate(self, request: Request) -> tuple[Any, None] | None:
        parts = get_authorization_header(request).split()
        if not parts or parts[0].lower() != KEYWORD:
            return None  # not ours: the JWT class (or nobody) handles it
        if len(parts) != 2:
            raise AuthenticationFailed(INVALID)
        try:
            raw = parts[1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise AuthenticationFailed(INVALID) from exc
        result = services.authenticate(raw)
        if result is None:
            raise AuthenticationFailed(INVALID)
        principal, scope = result
        rls.bind(scope)
        return principal, None

    def authenticate_header(self, request: Request) -> str:
        return 'ApiKey realm="api"'
