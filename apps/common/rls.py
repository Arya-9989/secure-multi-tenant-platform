"""The database scope that PostgreSQL row-level security enforces.

Application code decides *which* rows a caller may see with
:meth:`apps.common.tenancy.TenantQuerySet.visible_to`. Row-level security is a
second, independent layer inside the database (ADR 0001): every statement runs
under one :class:`DbScope`, and the policies only expose rows that match it.

The current scope lives in a ``ContextVar``. :mod:`apps.common.pgbackend`
applies it to every transaction as ``app.tenant_id`` / ``app.platform``, so no
query can run without it. With no scope the database shows no tenant rows at
all: forgetting to set one fails closed.

* Requests start with :data:`NO_SCOPE` (``RequestContextMiddleware``) and
  authentication binds the caller's scope (:func:`bind`).
* Code that must look across tenants says so with :func:`platform_scope`.
* Background work runs in the tenant recorded on it (:func:`tenant_scope`).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

TENANT_SETTING = "app.tenant_id"
PLATFORM_SETTING = "app.platform"


@dataclass(frozen=True, slots=True)
class DbScope:
    """One of: no scope, one tenant, or the whole platform."""

    tenant_id: uuid.UUID | None = None
    platform: bool = False

    def __post_init__(self) -> None:
        if self.platform and self.tenant_id is not None:
            raise ValueError("A scope is either one tenant or the whole platform, not both.")

    @property
    def setting_values(self) -> tuple[str, str]:
        """The values for ``app.tenant_id`` and ``app.platform``."""
        return (str(self.tenant_id) if self.tenant_id else "", "on" if self.platform else "")

    def __str__(self) -> str:
        if self.platform:
            return "platform"
        return f"tenant:{self.tenant_id}" if self.tenant_id else "none"


NO_SCOPE = DbScope()
PLATFORM = DbScope(platform=True)

_current: ContextVar[DbScope | None] = ContextVar("db_scope", default=None)
_process_default = NO_SCOPE


def for_tenant(tenant_id: uuid.UUID | str | None) -> DbScope:
    """The scope of one organization (:data:`NO_SCOPE` for ``None``)."""
    if tenant_id is None:
        return NO_SCOPE
    return DbScope(
        tenant_id=tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
    )


def current_scope() -> DbScope:
    scope = _current.get()
    return _process_default if scope is None else scope


@contextmanager
def scope(value: DbScope) -> Iterator[DbScope]:
    """Run the enclosed code under ``value``, restoring the previous scope afterwards."""
    token = _current.set(value)
    try:
        yield value
    finally:
        _current.reset(token)


def platform_scope() -> Any:
    """Explicitly look across every tenant (super admins, operators, system jobs)."""
    return scope(PLATFORM)


def tenant_scope(tenant_id: uuid.UUID | str | None) -> Any:
    return scope(for_tenant(tenant_id))


def bind(value: DbScope) -> None:
    """Set the scope for the rest of the enclosing :func:`scope` block.

    Authentication uses this: the request starts in :data:`NO_SCOPE` and, once
    the caller is known, continues in the caller's scope. The middleware's
    ``scope()`` block restores the previous value when the request ends.
    """
    _current.set(value)
    if value.tenant_id is not None:
        from apps.common.tracing import set_tenant  # noqa: PLC0415 - optional at import

        set_tenant(value.tenant_id)  # the request's span learns its tenant (ADR 0008)


def set_process_default(value: DbScope) -> None:
    """The scope of code that runs outside any :func:`scope` block (operator shells)."""
    global _process_default  # noqa: PLW0603 - a deliberate, process-wide switch
    _process_default = value
