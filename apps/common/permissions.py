from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from rest_framework.exceptions import NotFound
from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.views import APIView

from apps.accounts.roles import Perm, role_has_permission
from apps.common.tenancy import resolve_user

logger = logging.getLogger(__name__)


def required_permission(view: APIView, request: Request) -> Perm | None:
    """The permission a view requires for the current action (``None`` = undeclared)."""
    mapping: Mapping[str, Perm] = getattr(view, "required_permissions", {})
    key = getattr(view, "action", None) or (request.method or "").lower()
    return mapping.get(key)


class HasRolePermission(BasePermission):
    """RBAC check driven by ``view.required_permissions``.

    Fail-closed: an action that is not declared in the mapping is denied, so a
    newly added endpoint is inaccessible until someone decides who may use it.
    """

    def has_permission(self, request: Request, view: APIView) -> bool:
        user = resolve_user(request.user)
        method = (request.method or "").lower()
        if user is not None and (method not in view.http_method_names or not hasattr(view, method)):
            return True  # no handler: let DRF answer 405 rather than a misleading 403
        perm = required_permission(view, request)
        return user is not None and perm is not None and role_has_permission(user.role, perm)


class TenantObjectPermission(BasePermission):
    """Defense in depth behind queryset scoping.

    Objects normally arrive here already filtered by
    :meth:`TenantQuerySet.visible_to`. If a view ever bypasses that (e.g. a
    hand-written ``get_object``), this check still refuses foreign objects -
    and answers 404 rather than 403 so it does not confirm the object exists.
    """

    def has_object_permission(self, request: Request, view: APIView, obj: Any) -> bool:
        user = resolve_user(request.user)
        if user is None:
            return False
        if user.is_super_admin:
            return True
        tenant_id = getattr(obj, "tenant_id", None)
        if tenant_id is None or tenant_id != user.organization_id:
            logger.warning(
                "Tenant guard blocked cross-tenant object access",
                extra={"view": type(view).__name__, "object_type": type(obj).__name__},
            )
            raise NotFound
        return True
