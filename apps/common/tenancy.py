"""Tenant isolation primitives.

Isolation is enforced in one place - :meth:`TenantQuerySet.visible_to` - and
applied automatically by :class:`apps.common.views.TenantScopedViewSet` and
:class:`TenantScopedPrimaryKeyRelatedField`. The rules are deliberately
*fail-closed*: anything that is not an authenticated, active platform user
sees nothing, and a non-super-admin without an organization sees nothing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar, Self, TypeVar

from django.db import models
from rest_framework import serializers

from apps.common.principals import ServicePrincipal

if TYPE_CHECKING:
    from apps.accounts.models import User

_M = TypeVar("_M", bound=models.Model)


def resolve_user(candidate: object) -> User | None:
    """Return ``candidate`` if it is an authenticated, active platform user."""
    from apps.accounts.models import User  # noqa: PLC0415 - avoids an import cycle

    if isinstance(candidate, User) and candidate.is_authenticated and candidate.is_active:
        return candidate
    return None


def resolve_principal(candidate: object) -> User | ServicePrincipal | None:
    """A person (as :func:`resolve_user`) or a service holding an API key (ADR 0005)."""
    if isinstance(candidate, ServicePrincipal):
        return candidate
    return resolve_user(candidate)


class TenantQuerySet(models.QuerySet[_M]):
    """QuerySet for rows owned by an organization.

    ``tenant_field`` names the lookup that resolves to the owning
    organization's primary key (``"pk"`` for :class:`Organization` itself).
    """

    tenant_field: ClassVar[str] = "organization"

    def visible_to(self, candidate: object) -> Self:
        principal = resolve_principal(candidate)
        if principal is None:
            return self.none()
        if principal.is_super_admin:
            return self.all()
        if principal.organization_id is None:
            return self.none()
        return self.filter(**{self.tenant_field: principal.organization_id})


def tenant_id_of(obj: Any) -> Any:
    """The organization ID owning ``obj`` (models expose it as ``tenant_id``)."""
    return obj.tenant_id


class TenantScopedPrimaryKeyRelatedField(serializers.PrimaryKeyRelatedField):  # type: ignore[type-arg]
    """A PK relation that only resolves objects the requesting user may see.

    Without this, a writable foreign key is an IDOR vector: a caller could
    reference another tenant's object by ID. Foreign IDs are reported as
    "does not exist", identical to IDs that really do not exist.
    """

    def get_queryset(self) -> models.QuerySet[Any]:
        queryset = super().get_queryset()
        if not isinstance(queryset, TenantQuerySet):
            msg = f"{type(self).__name__} requires a TenantQuerySet."
            raise TypeError(msg)
        request = self.context.get("request")
        return queryset.visible_to(getattr(request, "user", None))
