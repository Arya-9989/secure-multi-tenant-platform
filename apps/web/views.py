"""The public landing page and the themed Swagger UI / Redoc views.

The landing page explains the security model. Wherever possible it renders
facts from the running code instead of repeating them: the role matrix comes
from :data:`apps.accounts.roles.ROLE_PERMISSIONS`, lifetimes and rate limits
from settings, audit event names from :class:`AuditAction`, and the status
line from the same checks as ``/health/ready/``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any, NamedTuple, cast

from django.conf import settings
from django.contrib.auth import password_validation
from django.contrib.staticfiles import finders
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse
from django.templatetags.static import static
from django.urls import reverse
from django.utils import timezone
from django.utils.csp import CSP
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_control
from django.views.decorators.csp import csp_override
from django.views.decorators.gzip import gzip_page
from django.views.decorators.http import condition
from django.views.generic import TemplateView
from drf_spectacular.utils import extend_schema
from drf_spectacular.views import SpectacularRedocView, SpectacularSwaggerSplitView
from rest_framework.request import Request
from rest_framework.response import Response

from apps.accounts.roles import ROLE_PERMISSIONS, Perm, Role
from apps.auditlogs.models import AuditAction
from apps.common.views import readiness_checks
from apps.web.content import TEST_SUITE

PERMISSION_LABELS: dict[Perm, str] = {
    Perm.ORGANIZATION_VIEW: "View organizations",
    Perm.ORGANIZATION_MANAGE: "Create and update organizations",
    Perm.USER_VIEW: "View users",
    Perm.USER_MANAGE: "Change roles, deactivate and reactivate users",
    Perm.INVITATION_MANAGE: "Invite people and revoke invitations",
    Perm.AUDIT_VIEW: "Query the audit log",
    Perm.SSO_MANAGE: "Configure single sign-on",
}

ROLE_SHORT_LABELS: dict[Role, str] = {
    Role.SUPER_ADMIN: "Super",
    Role.ORG_ADMIN: "Org admin",
    Role.MEMBER: "Member",
}

_PERIODS = {"s": "second", "m": "minute", "h": "hour", "d": "day"}


class Quantity(NamedTuple):
    value: int
    unit: str


def humanize_duration(delta: timedelta) -> Quantity:
    """The largest whole unit that expresses ``delta`` exactly (5 minutes, 1 day...)."""
    seconds = int(delta.total_seconds())
    for unit, size in (("day", 86_400), ("hour", 3_600), ("minute", 60)):
        if seconds >= size and seconds % size == 0:
            count = seconds // size
            return Quantity(count, unit if count == 1 else f"{unit}s")
    return Quantity(seconds, "second" if seconds == 1 else "seconds")


def humanize_rate(rate: str) -> Quantity:
    """A DRF throttle rate such as ``"10/min"`` as ``Quantity(10, "per minute")``."""
    count, _, period = rate.partition("/")
    return Quantity(int(count), f"per {_PERIODS[period[0]]}")


def password_min_length() -> int | None:
    """The enforced minimum, read from the configured validators."""
    for validator in password_validation.get_default_password_validators():
        if isinstance(validator, password_validation.MinimumLengthValidator):
            return validator.min_length
    return None


def role_matrix() -> dict[str, Any]:
    roles = list(Role)
    return {
        "roles": [
            {"code": role.value, "label": role.label, "short": ROLE_SHORT_LABELS[role]}
            for role in roles
        ],
        "rows": [
            {
                "code": perm.value,
                "label": PERMISSION_LABELS[perm],
                "cells": [perm in ROLE_PERMISSIONS[role] for role in roles],
            }
            for perm in Perm
        ],
    }


def suite_inventory() -> dict[str, Any]:
    total = sum(entry.tests for entry in TEST_SUITE)
    largest = max(entry.tests for entry in TEST_SUITE)
    return {
        "total": total,
        "files": [
            {
                "path": entry.path,
                "tests": entry.tests,
                "focus": entry.focus,
                # Bar length as a percentage of the largest file, for the chart.
                "share": round(entry.tests * 100 / largest),
            }
            for entry in TEST_SUITE
        ],
    }


# Compressed: the page carries no secret or request-reflected input for a
# compression oracle (BREACH) to recover, and gzip keeps the isolation story's
# inline SVG from slowing the first paint.
@method_decorator(gzip_page, name="dispatch")
@method_decorator(cache_control(no_cache=True, max_age=0), name="dispatch")
class LandingView(TemplateView):
    template_name = "web/landing.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        checks = readiness_checks()
        jwt = settings.SIMPLE_JWT
        rates = cast(Mapping[str, str], settings.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"])
        context.update(
            docs_enabled=settings.API_DOCS_ENABLED,
            status={
                "ready": all(result == "ok" for result in checks.values()),
                "checks": checks,
                "checked_at": timezone.now(),
            },
            matrix=role_matrix(),
            access_ttl=humanize_duration(jwt["ACCESS_TOKEN_LIFETIME"]),
            refresh_ttl=humanize_duration(jwt["REFRESH_TOKEN_LIFETIME"]),
            invitation_ttl=humanize_duration(settings.INVITATION_TTL),
            auth_rate=humanize_rate(rates["auth"]),
            password_min_length=password_min_length(),
            audit_actions=[action.value for action in AuditAction],
            suite=suite_inventory(),
        )
        return context


class ThemedSwaggerView(SpectacularSwaggerSplitView):
    """Swagger UI with the site's type, colours and dark mode.

    The split view serves the init script from a URL instead of inlining it,
    so the page runs under ``script-src 'self'``.
    """

    template_name = "web/swagger_ui.html"
    title = "API reference Â· Secure Multi-Tenant Platform"


# Redoc renders with styled-components, which inserts <style> elements at
# runtime, and builds its search index in a worker created from a blob: URL.
# Its page therefore allows styles carrying this response's nonce (handed to
# Redoc's `nonce` option) and blob: workers. Two style elements are inserted
# as the bundle loads, before a nonce can be set, so they are allowed by hash:
# the bundled perfect-scrollbar stylesheet and an empty element. Scripts stay
# 'self' only.
REDOC_STYLE_HASHES = (
    "'sha256-QMIg+bpjm3JdElJ388KYke01izlUW0UoNOeKjpMxdgc='",  # perfect-scrollbar CSS
    "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='",  # empty <style>
)
REDOC_CSP: Mapping[str, Sequence[str]] = {
    **cast(Mapping[str, Sequence[str]], settings.SECURE_CSP),
    "style-src": [CSP.SELF, CSP.NONCE, *REDOC_STYLE_HASHES],
    "worker-src": [CSP.SELF, "blob:"],
}

REDOC_BUNDLE = "drf_spectacular_sidecar/redoc/bundles/redoc.standalone.js"
REDOC_LOGO = "web/vendor/redoc/logo-mini.svg"


class _Patch(NamedTuple):
    find: str
    replace: Callable[[], str]
    why: str


# Edits to the vendored Redoc bundle. Each must match exactly once, so an
# upgrade that changes the bundle fails loudly (and in the tests) instead of
# silently shipping the original.
REDOC_PATCHES = (
    _Patch(
        "https://cdn.redoc.ly/redoc/logo-mini.svg",
        lambda: static(REDOC_LOGO),
        "its attribution logo is fetched from Redocly's CDN: a third-party request "
        "that the CSP blocks, logging an error on every page view",
    ),
    _Patch(
        ".h5`\n  border-bottom: 1px solid rgba(38, 50, 56, 0.3);\n  margin: 1em 0 1em 0;\n"
        "  color: rgba(38, 50, 56, 0.7);",
        lambda: (
            ".h3`\n  border-bottom: 1px solid var(--hairline-strong);\n  margin: 1em 0 1em 0;\n"
            "  color: var(--ink-2);"
        ),
        "section labels such as 'Request body schema' are <h5> directly under the "
        "operation's <h2>, skipping two heading levels for screen-reader navigation; "
        "their fixed colours are also meant for a light background only",
    ),
    _Patch(
        "color: #0e7c86;",
        lambda: "color: var(--accent-ink);",
        "regex patterns are drawn in a fixed teal that fails contrast in the dark theme",
    ),
)


@lru_cache(maxsize=1)
def self_hosted_redoc_bundle() -> tuple[bytes, str]:
    """The sidecar's Redoc bundle with :data:`REDOC_PATCHES` applied, and its digest."""
    path = finders.find(REDOC_BUNDLE)
    if not isinstance(path, str):
        raise ImproperlyConfigured(
            f"{REDOC_BUNDLE} not found; is drf-spectacular-sidecar installed?"
        )
    source = Path(path).read_text(encoding="utf-8")
    for patch in REDOC_PATCHES:
        if source.count(patch.find) != 1:
            msg = f"The Redoc bundle changed: expected {patch.find!r} exactly once ({patch.why})."
            raise ImproperlyConfigured(msg)
        source = source.replace(patch.find, patch.replace())
    content = source.encode()
    return content, hashlib.sha256(content).hexdigest()[:16]


def redoc_bundle_url() -> str:
    return f"{reverse('redoc-bundle')}?v={self_hosted_redoc_bundle()[1]}"


def _redoc_bundle_etag(request: HttpRequest) -> str:
    return self_hosted_redoc_bundle()[1]


@gzip_page
@condition(etag_func=_redoc_bundle_etag)
def redoc_bundle(request: HttpRequest) -> HttpResponse:
    """Serve the patched bundle. The URL carries its digest, so it caches forever."""
    response = HttpResponse(
        self_hosted_redoc_bundle()[0], content_type="text/javascript; charset=utf-8"
    )
    response["Cache-Control"] = "public, max-age=31536000, immutable"
    return response


@method_decorator(csp_override(REDOC_CSP), name="dispatch")
class ThemedRedocView(SpectacularRedocView):
    """Redoc with the site's theme, initialised from a static script (no inline JS)."""

    template_name = "web/redoc.html"
    title = "API reference · Secure Multi-Tenant Platform"

    @extend_schema(exclude=True)
    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        response: Response = super().get(request, *args, **kwargs)  # type: ignore[no-untyped-call]
        cast(dict[str, Any], response.data)["redoc_standalone"] = redoc_bundle_url()
        return response
