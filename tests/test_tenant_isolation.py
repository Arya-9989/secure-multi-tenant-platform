"""Tenant isolation: the core security guarantee of the platform.

Every tenant-scoped endpoint is exercised by users of organization A against
objects of organization B. The expected answer is computed from the RBAC
matrix: **404** when the role may perform the action (the object simply does
not exist for them) and **403** when the role may not perform it at all.
In both cases the target row must be unchanged.

``test_every_api_route_is_covered`` fails if a new route is added without
being added here, so isolation coverage cannot silently rot.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

import pytest
from django.contrib.auth.models import AnonymousUser
from django.db.models import Model
from django.urls import URLPattern, reverse
from rest_framework.exceptions import NotFound
from rest_framework.test import APIRequestFactory

from apps.accounts.models import Invitation, User
from apps.accounts.roles import Perm, role_has_permission
from apps.apikeys.models import ApiKey
from apps.auditlogs.models import AuditLog
from apps.common.permissions import TenantObjectPermission
from apps.common.views import TenantScopedViewSet
from apps.organizations.models import Organization
from apps.sso.models import OidcProvider
from config.urls import api_v1, router
from tests.conftest import ClientFactory, World

pytestmark = pytest.mark.django_db

TENANT_A_ACTORS = ("admin_a", "member_a")


@dataclass(frozen=True)
class ObjectCase:
    id: str
    method: str
    route: str
    target: str  # attribute of World: an object owned by organization B
    perm: Perm
    body: dict[str, Any] | None = None


OBJECT_CASES = (
    ObjectCase("org-retrieve", "get", "organization-detail", "org_b", Perm.ORGANIZATION_VIEW),
    ObjectCase(
        "org-update",
        "patch",
        "organization-detail",
        "org_b",
        Perm.ORGANIZATION_MANAGE,
        {"name": "Pwned"},
    ),
    ObjectCase("user-retrieve", "get", "user-detail", "admin_b", Perm.USER_VIEW),
    ObjectCase(
        "user-change-role", "patch", "user-detail", "member_b", Perm.USER_MANAGE, {"role": "MEMBER"}
    ),
    ObjectCase(
        "user-promote", "patch", "user-detail", "member_b", Perm.USER_MANAGE, {"role": "ORG_ADMIN"}
    ),
    ObjectCase("user-deactivate", "post", "user-deactivate", "member_b", Perm.USER_MANAGE),
    ObjectCase("user-reactivate", "post", "user-reactivate", "inactive_b", Perm.USER_MANAGE),
    ObjectCase(
        "invitation-retrieve", "get", "invitation-detail", "invitation_b", Perm.INVITATION_MANAGE
    ),
    ObjectCase(
        "invitation-revoke", "post", "invitation-revoke", "invitation_b", Perm.INVITATION_MANAGE
    ),
    ObjectCase(
        "invitation-resend", "post", "invitation-resend", "invitation_b", Perm.INVITATION_MANAGE
    ),
    ObjectCase("auditlog-retrieve", "get", "auditlog-detail", "audit_b", Perm.AUDIT_VIEW),
    ObjectCase("user-reset-mfa", "post", "user-reset-mfa", "member_b", Perm.USER_MANAGE),
    ObjectCase("ssoprovider-retrieve", "get", "ssoprovider-detail", "sso_b", Perm.SSO_MANAGE),
    ObjectCase(
        "ssoprovider-update",
        "patch",
        "ssoprovider-detail",
        "sso_b",
        Perm.SSO_MANAGE,
        {"enabled": False, "client_secret": "attacker-controlled"},
    ),
    ObjectCase("ssoprovider-delete", "delete", "ssoprovider-detail", "sso_b", Perm.SSO_MANAGE),
    ObjectCase("apikey-retrieve", "get", "apikey-detail", "api_key_b", Perm.API_KEY_MANAGE),
    ObjectCase("apikey-revoke", "post", "apikey-revoke", "api_key_b", Perm.API_KEY_MANAGE),
    ObjectCase(
        "apikey-rotate",
        "post",
        "apikey-rotate",
        "api_key_b",
        Perm.API_KEY_MANAGE,
        {"grace_minutes": 60},
    ),
)


@dataclass(frozen=True)
class ListCase:
    route: str
    perm: Perm
    model: type[Model]


LIST_CASES = (
    ListCase("organization-list", Perm.ORGANIZATION_VIEW, Organization),
    ListCase("user-list", Perm.USER_VIEW, User),
    ListCase("invitation-list", Perm.INVITATION_MANAGE, Invitation),
    ListCase("auditlog-list", Perm.AUDIT_VIEW, AuditLog),
    ListCase("ssoprovider-list", Perm.SSO_MANAGE, OidcProvider),
    ListCase("apikey-list", Perm.API_KEY_MANAGE, ApiKey),
)


def _snapshot(obj: Model) -> dict[str, Any]:
    return type(obj)._default_manager.filter(pk=obj.pk).values().get()


def _foreign_ids(model: type[Model], world: World) -> set[str]:
    org_b = world.org_b
    if model is Organization:
        return {str(org_b.pk)}
    return {
        str(pk)
        for pk in model._default_manager.filter(organization=org_b).values_list("pk", flat=True)
    }


@pytest.mark.parametrize("actor_name", TENANT_A_ACTORS)
@pytest.mark.parametrize("case", OBJECT_CASES, ids=lambda c: c.id)
def test_cross_tenant_object_access_is_denied(
    world: World, client_for: ClientFactory, actor_name: str, case: ObjectCase
) -> None:
    actor: User = getattr(world, actor_name)
    target: Model = getattr(world, case.target)
    before = _snapshot(target)

    url = reverse(case.route, args=[target.pk])
    response = getattr(client_for(actor), case.method)(url, case.body or {}, format="json")

    expected = 404 if role_has_permission(actor.role, case.perm) else 403
    assert response.status_code == expected, response.content
    assert _snapshot(target) == before


@pytest.mark.parametrize("case", OBJECT_CASES, ids=lambda c: c.id)
def test_super_admin_is_not_tenant_restricted(
    world: World, client_for: ClientFactory, case: ObjectCase
) -> None:
    """Positive control: the same requests are routable and authorized for operators."""
    target: Model = getattr(world, case.target)
    url = reverse(case.route, args=[target.pk])
    response = getattr(client_for(world.super_admin), case.method)(
        url, case.body or {}, format="json"
    )
    assert response.status_code in {200, 201, 204}, response.content


@pytest.mark.parametrize("actor_name", TENANT_A_ACTORS)
@pytest.mark.parametrize("case", LIST_CASES, ids=lambda c: c.route)
def test_list_endpoints_never_return_foreign_rows(
    world: World, client_for: ClientFactory, actor_name: str, case: ListCase
) -> None:
    actor: User = getattr(world, actor_name)
    client = client_for(actor)
    url = reverse(case.route)
    foreign = _foreign_ids(case.model, world)
    assert foreign, "fixture must contain foreign rows for this to be meaningful"

    # Plain listing, and listing that explicitly asks for the other tenant.
    param_sets: list[dict[str, str]] = [
        {},
        {"organization": str(world.org_b.pk)},
        {"search": "b.test"},
    ]
    for params in param_sets:
        response = client.get(url, {"page_size": "100", **params})
        if not role_has_permission(actor.role, case.perm):
            assert response.status_code == 403
            continue
        assert response.status_code == 200, response.content
        returned = {row["id"] for row in response.json()["results"]}
        assert not returned & foreign
        if not params:
            assert returned, "positive control: own-tenant rows must be visible"


def test_member_list_contains_exactly_own_tenant(world: World, client_for: ClientFactory) -> None:
    response = client_for(world.member_a).get(reverse("user-list"))
    emails = {row["email"] for row in response.json()["results"]}
    assert emails == {"admin@a.test", "member@a.test", "former@a.test"}


@pytest.mark.parametrize("actor_name", TENANT_A_ACTORS)
def test_cannot_invite_into_another_tenant_by_reference(
    world: World, client_for: ClientFactory, actor_name: str
) -> None:
    actor: User = getattr(world, actor_name)
    response = client_for(actor).post(
        reverse("invitation-list"),
        {"email": "mole@evil.test", "role": "MEMBER", "organization": str(world.org_b.pk)},
    )
    if role_has_permission(actor.role, Perm.INVITATION_MANAGE):
        assert response.status_code == 400
        # Same message as for an ID that does not exist: no existence oracle.
        assert "does not exist" in str(response.json()["organization"])
    else:
        assert response.status_code == 403
    assert not Invitation.objects.filter(email="mole@evil.test").exists()


@pytest.mark.parametrize("actor_name", TENANT_A_ACTORS)
def test_cannot_create_tenants(world: World, client_for: ClientFactory, actor_name: str) -> None:
    response = client_for(getattr(world, actor_name)).post(
        reverse("organization-list"), {"name": "Shadow Org"}
    )
    assert response.status_code == 403
    assert not Organization.objects.filter(name="Shadow Org").exists()


def test_unknown_and_foreign_ids_are_indistinguishable(
    world: World, client_for: ClientFactory
) -> None:
    client = client_for(world.admin_a)
    foreign = client.get(reverse("user-detail", args=[world.admin_b.pk]))
    missing = client.get(reverse("user-detail", args=["00000000-0000-0000-0000-000000000000"]))
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()


# ---------------------------------------------------------------- structural guarantees
SELF_SERVICE_OR_PUBLIC_ROUTES = {
    "auth-login",
    "auth-refresh",
    "auth-logout",
    "auth-logout-all",
    "auth-me",
    "auth-password-change",
    "invitation-accept",
    # The signed-in user's own second factors; foreign credential IDs are covered by
    # test_mfa.py::test_a_foreign_security_key_is_not_found.
    "mfa-status",
    "mfa-totp-setup",
    "mfa-totp-confirm",
    "mfa-totp-disable",
    "mfa-recovery-codes",
    "mfa-webauthn-register",
    "mfa-webauthn-register-complete",
    "mfa-webauthn-remove",
    # The public second sign-in step and SSO flow (test_mfa.py, test_sso.py).
    "mfa-verify",
    "mfa-webauthn-begin",
    "mfa-webauthn-complete",
    "sso-login",
    "sso-callback",
    "sso-exchange",
}
COVERED_ROUTES = (
    {c.route for c in OBJECT_CASES}
    | {c.route for c in LIST_CASES}  # list + create share the same route name
)


def test_every_api_route_is_covered() -> None:
    names = {p.name for p in api_v1 if isinstance(p, URLPattern) and p.name}
    uncovered = names - COVERED_ROUTES - SELF_SERVICE_OR_PUBLIC_ROUTES
    assert not uncovered, f"Add isolation cases for new routes: {sorted(uncovered)}"


def test_every_routed_viewset_is_tenant_scoped_and_declares_permissions() -> None:
    for prefix, viewset, _basename in router.registry:
        assert issubclass(viewset, TenantScopedViewSet), prefix
    for pattern in router.urls:
        callback = cast(Any, pattern.callback)
        viewset = callback.cls
        for action in callback.actions.values():
            if action in {"update", "destroy"} or not hasattr(viewset, action):
                continue
            assert action in viewset.required_permissions, f"{viewset.__name__}.{action}"


def test_object_guard_blocks_objects_that_bypassed_queryset_scoping(world: World) -> None:
    """Defense in depth: even a view that fetched a foreign object cannot return it."""
    request = APIRequestFactory().get("/")
    request.user = world.admin_a
    guard = TenantObjectPermission()
    assert guard.has_object_permission(request, None, world.member_a)  # type: ignore[arg-type]
    with pytest.raises(NotFound):
        guard.has_object_permission(request, None, world.member_b)  # type: ignore[arg-type]
    with pytest.raises(NotFound):
        guard.has_object_permission(request, None, object())  # type: ignore[arg-type]


def test_scoping_fails_closed_for_anonymous_and_orgless_users(world: World) -> None:
    assert not User.objects.visible_to(AnonymousUser()).exists()
    assert not User.objects.visible_to(None).exists()
    assert not User.objects.visible_to(world.inactive_a).exists()
    orphan = User(email="ghost@x.test", role="MEMBER", organization=None)
    assert not User.objects.visible_to(orphan).exists()
