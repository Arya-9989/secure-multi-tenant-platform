"""The public landing page and the themed Swagger UI / Redoc views.

The landing page explains the security model. Wherever possible it renders
facts from the running code instead of repeating them: the role matrix comes
from :data:`apps.accounts.roles.ROLE_PERMISSIONS`, lifetimes and rate limits
from settings, audit event names from :class:`AuditAction`, and the status
line from the same checks as ``/health/ready/``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from typing import Any, NamedTuple, cast

from django.conf import settings
from django.contrib.auth import password_validation
from django.utils import timezone
from django.utils.csp import CSP
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_control
from django.views.decorators.csp import csp_override
from django.views.generic import TemplateView
from drf_spectacular.views import SpectacularRedocView, SpectacularSwaggerSplitView

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
    title = "API reference · Secure Multi-Tenant Platform"


# Redoc renders with styled-components, which inserts <style> elements at
# runtime, and builds its search index in a worker created from a blob: URL.
# Its page therefore allows styles carrying this response's nonce (handed to
# Redoc's `nonce` option) and blob: workers. Two style elements are inserted
# as the bundle loads, before a nonce can be set, so they are allowed by hash:
# the bundled perfect-scrollbar stylesheet and an empty element. Scripts stay
# 'self' only. (Redoc also requests its logo from cdn.redoc.ly; img-src blocks
# that, and Redoc then drops the image.)
REDOC_STYLE_HASHES = (
    "'sha256-QMIg+bpjm3JdElJ388KYke01izlUW0UoNOeKjpMxdgc='",  # perfect-scrollbar CSS
    "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='",  # empty <style>
)
REDOC_CSP: Mapping[str, Sequence[str]] = {
    **cast(Mapping[str, Sequence[str]], settings.SECURE_CSP),
    "style-src": [CSP.SELF, CSP.NONCE, *REDOC_STYLE_HASHES],
    "worker-src": [CSP.SELF, "blob:"],
}


@method_decorator(csp_override(REDOC_CSP), name="dispatch")
class ThemedRedocView(SpectacularRedocView):
    """Redoc with the site's theme, initialised from a static script (no inline JS)."""

    template_name = "web/redoc.html"
    title = "API reference · Secure Multi-Tenant Platform"
