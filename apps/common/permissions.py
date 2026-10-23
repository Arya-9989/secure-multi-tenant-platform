from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from rest_framework.exceptions import NotFound
from rest_framework.permissions import SAFE_METHODS, BasePermission
from rest_framework.request import Request
from rest_framework.views import APIView

from apps.accounts.roles import Perm, role_has_permission
from apps.common.principals import ServicePrincipal
from apps.common.tenancy import resolve_principal

logger = logging.getLogger(__name__)


def required_permission(view: APIView, request: Request) -> Perm | None:
    """The permission a view requires for the current action (``None`` = undeclared)."""
    mapping: Mapping[str, Perm] = getattr(view, "required_permissions", {})
    key = getattr(view, "action", None) or (request.method or "").lower()
    return mapping.get(key)


def required_api_key_scope(view: APIView, request: Request) -> str | None:
    """The API-key scope a view requires for the current action (``None`` = keys refused)."""
    mapping: Mapping[str, str] = getattr(view, "api_key_scopes", {})
    key = getattr(view, "action", None) or (request.method or "").lower()
    return mapping.get(key)


class HasRolePermission(BasePermission):
    """RBAC check driven by ``view.required_permissions`` (people) and
    ``view.api_key_scopes`` (services, ADR 0005).

    Fail-closed: an action that is not declared in the mapping is denied, so a
    newly added endpoint is inaccessible until someone decides who may use it.
    API keys are read-only: an unsafe method is refused whatever is declared.
    """

    def has_permission(self, request: Request, view: APIView) -> bool:
        principal = resolve_principal(request.user)
        method = (request.method or "").lower()
        if principal is not None and (
            method not in view.http_method_names or not hasattr(view, method)
        ):
            return True  # no handler: let DRF answer 405 rather than a misleading 403
        if isinstance(principal, ServicePrincipal):
            scope = required_api_key_scope(view, request)
            return (
                request.method in SAFE_METHODS and scope is not None and scope in principal.scopes
            )
        perm = required_permission(view, request)
        return (
            principal is not None and perm is not None and role_has_permission(principal.role, perm)
        )


class TenantObjectPermission(BasePermission):
    """Defense in depth behind queryset scoping.

    Objects normally arrive here already filtered by
    :meth:`TenantQuerySet.visible_to`. If a view ever bypasses that (e.g. a
    hand-written ``get_object``), this check still refuses foreign objects -
    and answers 404 rather than 403 so it does not confirm the object exists.
    """

    def has_object_permission(self, request: Request, view: APIView, obj: Any) -> bool:
        principal = resolve_principal(request.user)
        if principal is None:
            return False
        if principal.is_super_admin:
            return True
        tenant_id = getattr(obj, "tenant_id", None)
        if tenant_id is None or tenant_id != principal.organization_id:
            logger.warning(
                "Tenant guard blocked cross-tenant object access",
                extra={"view": type(view).__name__, "object_type": type(obj).__name__},
            )
            raise NotFound
        return True
