"""Callers that are not people: services authenticated with an API key (ADR 0005).

A :class:`ServicePrincipal` stands in for ``request.user``. It belongs to one
organization, is never a super admin, and is authorized by its scopes rather
than by a role. Code that needs a person (every write, every service function)
uses :func:`apps.common.tenancy.resolve_user`, which never returns one of these.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ServicePrincipal:
    key_id: uuid.UUID
    key_prefix: str
    organization_id: uuid.UUID
    scopes: frozenset[str]

    is_authenticated = True
    is_active = True
    is_super_admin = False
    is_staff = False

    @property
    def pk(self) -> str:
        """The throttle identity: one bucket per key."""
        return f"apikey:{self.key_id}"

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.organization_id

    def __str__(self) -> str:
        return f"API key {self.key_prefix}"
