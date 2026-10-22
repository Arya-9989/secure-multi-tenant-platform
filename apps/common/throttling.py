"""Rate limiting keyed on the same client address the audit log records.

DRF's stock throttles identify anonymous clients by ``X-Forwarded-For`` whenever
``NUM_PROXIES`` is unset, and that header is whatever the client wants it to be:
a fresh value per request would buy a fresh budget. These classes key on
:func:`apps.common.net.get_client_ip` instead, which trusts the header only
behind ``NUM_PROXIES`` configured proxies, so the throttle and the audit trail
always agree on who the client is.
"""

from __future__ import annotations

from typing import Any, cast

from django.http import HttpRequest
from rest_framework.request import Request
from rest_framework.throttling import (
    AnonRateThrottle,
    ScopedRateThrottle,
    SimpleRateThrottle,
    UserRateThrottle,
)

from apps.common.net import get_client_ip


class ClientIPIdentMixin:
    def get_ident(self, request: Request | HttpRequest) -> str:
        return get_client_ip(request) or request.META.get("REMOTE_ADDR") or "unknown"


class ClientAnonRateThrottle(ClientIPIdentMixin, AnonRateThrottle):
    pass


class ClientUserRateThrottle(ClientIPIdentMixin, UserRateThrottle):
    pass


class ClientScopedRateThrottle(ClientIPIdentMixin, ScopedRateThrottle):
    pass


class AdminLoginThrottle(ClientIPIdentMixin, SimpleRateThrottle):
    """The API's credential rate (``THROTTLE_AUTH``) applied to Django admin sign-ins."""

    scope = "auth"

    def get_cache_key(self, request: Any, view: Any) -> str:
        return self.cache_format % {"scope": "admin-login", "ident": self.get_ident(request)}

    def allows(self, request: HttpRequest) -> bool:
        """Count one attempt; ``False`` once the client is over the rate."""
        return self.allow_request(cast(Any, request), cast(Any, None))
