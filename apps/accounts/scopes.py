"""Pre-authentication scope resolution (row-level security, ADR 0001).

Before a caller is authenticated the database scope is empty, so the account a
sign-in, token refresh or invitation refers to is invisible. These functions
look up *only the tenant* of that account in a short platform block; the rest
of the flow then runs in that tenant's scope, never the platform's (except for
super admins, whose scope is the platform).
"""

from __future__ import annotations

import uuid
from typing import Any

from apps.accounts.roles import Role
from apps.common import rls


def scope_for_account(*, user_id: Any = None, email: str | None = None) -> rls.DbScope:
    """The scope that may load this account; :data:`rls.NO_SCOPE` when unknown."""
    from apps.accounts.models import User, normalize_email  # noqa: PLC0415 - import cycle

    if email is not None:
        lookup: dict[str, Any] = {"email": normalize_email(email)}
    else:
        try:
            lookup = {"pk": uuid.UUID(str(user_id))}
        except ValueError:
            return rls.NO_SCOPE
    with rls.platform_scope():
        row = User.objects.filter(**lookup).values_list("organization_id", "role").first()
    if row is None:
        return rls.NO_SCOPE
    # Super admins have no organization (a check constraint guarantees it).
    organization_id: uuid.UUID | None = row[0]
    role: str = row[1]
    if organization_id is None:
        return rls.PLATFORM if role == Role.SUPER_ADMIN else rls.NO_SCOPE
    return rls.for_tenant(organization_id)


def scope_for_invitation(token_hash: str) -> rls.DbScope:
    """The scope of the organization an invitation token belongs to."""
    from apps.accounts.models import Invitation  # noqa: PLC0415 - import cycle

    with rls.platform_scope():
        organization_id = (
            Invitation.objects.filter(token_hash=token_hash)
            .values_list("organization_id", flat=True)
            .first()
        )
    return rls.for_tenant(organization_id)
