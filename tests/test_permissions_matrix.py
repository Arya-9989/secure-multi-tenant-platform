"""The README's roles/permissions matrix, executed.

Each row is (endpoint, expected status for SUPER_ADMIN, ORG_ADMIN, MEMBER),
always against objects in the caller's *own* tenant (organization A), so this
tests RBAC in isolation from tenant scoping.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest
from django.urls import reverse

from apps.accounts.roles import ROLE_PERMISSIONS, Perm, Role
from tests.conftest import ClientFactory, World

pytestmark = pytest.mark.django_db


@dataclass(frozen=True)
class Row:
    id: str
    method: str
    url: Callable[[World], str]
    expected: tuple[int, int, int]  # SUPER_ADMIN, ORG_ADMIN, MEMBER
    body: Callable[[World], dict[str, Any]] | None = None


MATRIX = (
    Row("org-list", "get", lambda w: reverse("organization-list"), (200, 200, 200)),
    Row(
        "org-retrieve",
        "get",
        lambda w: reverse("organization-detail", args=[w.org_a.pk]),
        (200, 200, 200),
    ),
    Row(
        "org-create",
        "post",
        lambda w: reverse("organization-list"),
        (201, 403, 403),
        lambda w: {"name": "Initech"},
    ),
    Row(
        "org-update",
        "patch",
        lambda w: reverse("organization-detail", args=[w.org_a.pk]),
        (200, 403, 403),
        lambda w: {"name": "Acme Renamed"},
    ),
    Row("user-list", "get", lambda w: reverse("user-list"), (200, 200, 200)),
    Row(
        "user-retrieve",
        "get",
        lambda w: reverse("user-detail", args=[w.member_a.pk]),
        (200, 200, 200),
    ),
    Row(
        "user-change-role",
        "patch",
        lambda w: reverse("user-detail", args=[w.member_a.pk]),
        (200, 200, 403),
        lambda w: {"role": "ORG_ADMIN"},
    ),
    Row(
        "user-deactivate",
        "post",
        lambda w: reverse("user-deactivate", args=[w.member_a.pk]),
        (200, 200, 403),
    ),
    Row(
        "user-reactivate",
        "post",
        lambda w: reverse("user-reactivate", args=[w.inactive_a.pk]),
        (200, 200, 403),
    ),
    Row("invitation-list", "get", lambda w: reverse("invitation-list"), (200, 200, 403)),
    Row(
        "invitation-create",
        "post",
        lambda w: reverse("invitation-list"),
        (201, 201, 403),
        lambda w: {"email": "new@a.test", "role": "MEMBER", "organization": str(w.org_a.pk)},
    ),
    Row(
        "invitation-revoke",
        "post",
        lambda w: reverse("invitation-revoke", args=[w.invitation_a.pk]),
        (200, 200, 403),
    ),
    Row("auditlog-list", "get", lambda w: reverse("auditlog-list"), (200, 200, 403)),
    Row(
        "auditlog-retrieve",
        "get",
        lambda w: reverse("auditlog-detail", args=[w.audit_a.pk]),
        (200, 200, 403),
    ),
    Row(
        "user-reset-mfa",
        "post",
        lambda w: reverse("user-reset-mfa", args=[w.member_a.pk]),
        (204, 204, 403),
    ),
    Row("ssoprovider-list", "get", lambda w: reverse("ssoprovider-list"), (200, 200, 403)),
    Row(
        "ssoprovider-retrieve",
        "get",
        lambda w: reverse("ssoprovider-detail", args=[w.sso_a.pk]),
        (200, 200, 403),
    ),
    Row(
        "ssoprovider-update",
        "patch",
        lambda w: reverse("ssoprovider-detail", args=[w.sso_a.pk]),
        (200, 200, 403),
        lambda w: {"enabled": False},
    ),
    Row("apikey-list", "get", lambda w: reverse("apikey-list"), (200, 200, 403)),
    Row(
        "apikey-create",
        "post",
        lambda w: reverse("apikey-list"),
        (201, 201, 403),
        lambda w: {"name": "BI", "scopes": ["users:read"], "organization": str(w.org_a.pk)},
    ),
    Row(
        "apikey-revoke",
        "post",
        lambda w: reverse("apikey-revoke", args=[w.api_key_a.pk]),
        (200, 200, 403),
    ),
    Row("me", "get", lambda w: reverse("auth-me"), (200, 200, 200)),
)

ROLES = (("super_admin", 0), ("admin_a", 1), ("member_a", 2))


@pytest.mark.parametrize(("actor_name", "column"), ROLES, ids=[r[0] for r in ROLES])
@pytest.mark.parametrize("row", MATRIX, ids=lambda r: r.id)
def test_permission_matrix(
    world: World, client_for: ClientFactory, actor_name: str, column: int, row: Row
) -> None:
    client = client_for(getattr(world, actor_name))
    body = row.body(world) if row.body else {}
    response = getattr(client, row.method)(row.url(world), body, format="json")
    assert response.status_code == row.expected[column], response.content


@pytest.mark.parametrize("row", MATRIX, ids=lambda r: r.id)
def test_anonymous_requests_are_rejected(world: World, api_client: Any, row: Row) -> None:
    response = getattr(api_client, row.method)(row.url(world), {}, format="json")
    assert response.status_code == 401


def test_role_matrix_shape() -> None:
    """Pin the matrix so any change to it is a deliberate, reviewed diff."""
    assert ROLE_PERMISSIONS[Role.SUPER_ADMIN] == frozenset(Perm)
    assert ROLE_PERMISSIONS[Role.ORG_ADMIN] == frozenset(Perm) - {Perm.ORGANIZATION_MANAGE}
    assert ROLE_PERMISSIONS[Role.MEMBER] == {Perm.ORGANIZATION_VIEW, Perm.USER_VIEW}
