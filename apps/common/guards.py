"""Authorization guards for the service layer.

Views already enforce RBAC and tenant scoping, but services re-check both so
they remain safe when called from somewhere else (a management command, a
future background job, a new view that forgets the base class).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rest_framework.exceptions import NotFound, PermissionDenied

from apps.accounts.roles import Perm, role_has_permission

if TYPE_CHECKING:
    from apps.accounts.models import User


def require_permission(actor: User, perm: Perm) -> None:
    if not actor.is_active or not role_has_permission(actor.role, perm):
        raise PermissionDenied


def require_same_tenant(actor: User, obj: Any) -> None:
    if actor.is_super_admin:
        return
    if actor.organization_id is None or obj.tenant_id != actor.organization_id:
        raise NotFound
