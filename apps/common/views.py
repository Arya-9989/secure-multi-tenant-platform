from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, ClassVar, TypeVar

from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.db import connection
from django.db.models import Model, QuerySet
from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework import serializers, status
from rest_framework.exceptions import NotAuthenticated
from rest_framework.permissions import AllowAny, BasePermission, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

from apps.accounts.roles import ApiScope, Perm
from apps.common.permissions import HasRolePermission, TenantObjectPermission
from apps.common.tenancy import TenantQuerySet, resolve_user

if TYPE_CHECKING:
    from rest_framework.permissions import _SupportsHasPermission

    from apps.accounts.models import User

logger = logging.getLogger(__name__)

_M = TypeVar("_M", bound=Model)
UUID_PATTERN = "[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}"


class TenantScopedViewSet(GenericViewSet[_M]):
    """Base class for every API view over tenant-owned data.

    It centralises the three layers of access control so individual views
    cannot forget one of them:

    1. ``IsAuthenticated`` + :class:`HasRolePermission` - *may this role call
       this action at all?* (driven by ``required_permissions``).
    2. :meth:`TenantQuerySet.visible_to` - *which rows exist for this caller?*
       Foreign rows are simply absent, so lookups yield 404.
    3. :class:`TenantObjectPermission` - a last-line object check.

    Subclasses may add permissions via ``permission_classes`` but cannot remove
    these layers.
    """

    permission_classes: Sequence[type[BasePermission]] = ()
    required_permissions: ClassVar[Mapping[str, Perm]] = {}
    # Read actions a service's API key may call, and the scope each needs (ADR 0005).
    api_key_scopes: ClassVar[Mapping[str, ApiScope]] = {}
    lookup_value_regex = UUID_PATTERN

    @property
    def actor(self) -> User:
        user = resolve_user(self.request.user)
        if user is None:  # unreachable behind IsAuthenticated; keeps types honest
            raise NotAuthenticated
        return user

    def get_permissions(self) -> Sequence[_SupportsHasPermission]:
        return [
            IsAuthenticated(),
            HasRolePermission(),
            *super().get_permissions(),
            TenantObjectPermission(),
        ]

    def get_queryset(self) -> QuerySet[_M]:
        queryset = super().get_queryset()
        if not isinstance(queryset, TenantQuerySet):
            msg = f"{type(self).__name__}.queryset must be a TenantQuerySet."
            raise ImproperlyConfigured(msg)
        return queryset.visible_to(self.request.user)


_health_response = inline_serializer(
    "HealthStatus",
    fields={
        "status": serializers.ChoiceField(choices=["ok", "unavailable"]),
        "checks": serializers.DictField(child=serializers.CharField(), required=False),
    },
)


class _ProbeView(APIView):
    authentication_classes = ()
    permission_classes = (AllowAny,)
    throttle_classes = ()


class LivenessView(_ProbeView):
    """The process is up and serving requests. Does not touch dependencies."""

    @extend_schema(tags=["health"], responses={200: _health_response}, auth=[])
    def get(self, request: Request) -> Response:
        return Response({"status": "ok"})


class ReadinessView(_ProbeView):
    """The app can serve traffic: the database and cache are reachable."""

    @extend_schema(
        tags=["health"], responses={200: _health_response, 503: _health_response}, auth=[]
    )
    def get(self, request: Request) -> Response:
        checks = readiness_checks()
        healthy = all(result == "ok" for result in checks.values())
        return Response(
            {"status": "ok" if healthy else "unavailable", "checks": checks},
            status=status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE,
        )


def readiness_checks() -> dict[str, str]:
    """Probe every dependency the app needs to serve traffic (``"ok"`` or ``"error"``)."""
    return {"database": _check_database(), "cache": _check_cache()}


def _check_database() -> str:
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except Exception:
        logger.exception("Readiness check failed: database")
        return "error"
    return "ok"


def _check_cache() -> str:
    try:
        cache.set("health:probe", "1", timeout=5)
        if cache.get("health:probe") != "1":
            return "error"
    except Exception:
        logger.exception("Readiness check failed: cache")
        return "error"
    return "ok"
