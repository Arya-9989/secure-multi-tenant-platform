"""Scoped API keys for services (ADR 0005): tenant-bound, hashed, read-only, expiring."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.apikeys.models import ApiKey
from apps.auditlogs.models import AuditAction, AuditLog
from apps.common.permissions import TenantObjectPermission
from apps.common.tenancy import TenantQuerySet
from apps.organizations.models import Organization
from config.urls import router
from tests.conftest import POSTGRES, ClientFactory, World

pytestmark = pytest.mark.django_db

KEYS = "/api/v1/api-keys/"


def issue(
    world: World, client_for: ClientFactory, scopes: list[str], **extra: Any
) -> dict[str, Any]:
    response = client_for(world.admin_a).post(
        KEYS, {"name": "Directory sync", "scopes": scopes, **extra}, format="json"
    )
    assert response.status_code == 201, response.content
    body: dict[str, Any] = response.json()
    return body


def service(key: str) -> APIClient:
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"ApiKey {key}")
    return client


# ---------------------------------------------------------------- issuing
def test_a_key_is_shown_once_and_stored_as_a_hash(world: World, client_for: ClientFactory) -> None:
    body = issue(world, client_for, ["users:read", "audit:read"])
    key = body["key"]
    assert key.startswith(f"{body['prefix']}_")
    assert body["prefix"].startswith("mtk_")
    assert body["scopes"] == ["audit:read", "users:read"]
    assert body["status"] == "active"
    stored = ApiKey.objects.filter(pk=body["id"]).values().get()
    secret = key.split("_", 2)[2]  # mtk_<prefix>_<secret>; the secret may contain "_"
    assert secret not in str(stored)
    assert stored["expires_at"] - stored["created_at"] == timedelta(days=90)

    listed = client_for(world.admin_a).get(KEYS).json()["results"]
    detail = client_for(world.admin_a).get(f"{KEYS}{body['id']}/").json()
    for shown in (listed, detail):
        assert secret not in str(shown)
        assert "key" not in (shown[0] if isinstance(shown, list) else shown)
    event = AuditLog.objects.get(action=AuditAction.API_KEY_CREATED)
    assert event.metadata["scopes"] == ["audit:read", "users:read"]
    assert secret not in str(event.metadata)


@pytest.mark.parametrize(
    "body",
    [
        {"scopes": []},
        {"scopes": ["users:write"]},
        {"scopes": ["users:read"], "expires_in_days": 0},
        {"scopes": ["users:read"], "expires_in_days": 366},
        {"scopes": ["users:read"], "organization": "00000000-0000-0000-0000-000000000000"},
        {"scopes": ["users:read"], "role": "SUPER_ADMIN"},
    ],
    ids=["no-scope", "write-scope", "zero-days", "over-a-year", "unknown-org", "unknown-field"],
)
def test_key_requests_are_validated(
    world: World, client_for: ClientFactory, body: dict[str, Any]
) -> None:
    response = client_for(world.admin_a).post(KEYS, {"name": "x", **body}, format="json")
    assert response.status_code == 400


def test_org_admins_cannot_issue_keys_for_another_tenant(
    world: World, client_for: ClientFactory
) -> None:
    response = client_for(world.admin_a).post(
        KEYS,
        {"name": "mole", "scopes": ["users:read"], "organization": str(world.org_b.pk)},
        format="json",
    )
    assert response.status_code == 400
    assert "does not exist" in str(response.json()["organization"])
    assert not ApiKey.objects.filter(name="mole").exists()


def test_super_admins_issue_keys_for_a_named_tenant(
    world: World, client_for: ClientFactory
) -> None:
    client = client_for(world.super_admin)
    assert (
        client.post(KEYS, {"name": "x", "scopes": ["users:read"]}, format="json").status_code == 400
    )
    response = client.post(
        KEYS,
        {"name": "x", "scopes": ["users:read"], "organization": str(world.org_b.pk)},
        format="json",
    )
    assert response.status_code == 201
    users = service(response.json()["key"]).get("/api/v1/users/").json()["results"]
    assert {row["organization"] for row in users} == {str(world.org_b.pk)}


def test_inactive_organizations_get_no_keys(world: World, client_for: ClientFactory) -> None:
    Organization.objects.filter(pk=world.org_b.pk).update(is_active=False)
    response = client_for(world.super_admin).post(
        KEYS,
        {"name": "x", "scopes": ["users:read"], "organization": str(world.org_b.pk)},
        format="json",
    )
    assert response.status_code == 400


# ---------------------------------------------------------------- using a key
def test_a_key_reads_its_own_tenant_only(world: World, client_for: ClientFactory) -> None:
    client = service(issue(world, client_for, ["users:read", "organization:read"])["key"])
    users = client.get("/api/v1/users/", {"page_size": 100}).json()["results"]
    assert {row["organization"] for row in users} == {str(world.org_a.pk)}
    assert (
        client.get("/api/v1/users/", {"organization": str(world.org_b.pk)}).json()["results"] == []
    )
    foreign = client.get(f"/api/v1/users/{world.admin_b.pk}/")
    missing = client.get("/api/v1/users/00000000-0000-0000-0000-000000000000/")
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()
    orgs = client.get("/api/v1/organizations/").json()["results"]
    assert [row["id"] for row in orgs] == [str(world.org_a.pk)]


@pytest.mark.parametrize(
    ("method", "url", "body"),
    [
        ("get", "/api/v1/audit-logs/", None),  # a scope the key lacks
        ("get", "/api/v1/invitations/", None),
        ("post", "/api/v1/invitations/", {"email": "x@a.test", "role": "MEMBER"}),
        ("patch", "user-detail", {"role": "ORG_ADMIN"}),
        ("post", "user-deactivate", None),
        ("get", "/api/v1/api-keys/", None),  # keys never manage keys
        ("post", "/api/v1/api-keys/", {"name": "x", "scopes": ["users:read"]}),
        ("get", "/api/v1/sso-providers/", None),
    ],
)
def test_scopes_are_enforced_per_endpoint_and_keys_never_write(
    world: World, client_for: ClientFactory, method: str, url: str, body: Any
) -> None:
    client = service(issue(world, client_for, ["users:read"])["key"])
    if not url.startswith("/"):
        url = reverse(url, args=[world.member_a.pk])
    response = getattr(client, method)(url, body or {}, format="json")
    assert response.status_code == 403, response.content
    world.member_a.refresh_from_db()
    assert (world.member_a.role, world.member_a.is_active) == ("MEMBER", True)
    assert not ApiKey.objects.filter(name="x").exists()


def test_an_audit_key_sees_its_tenants_events(world: World, client_for: ClientFactory) -> None:
    client = service(issue(world, client_for, ["audit:read"])["key"])
    rows = client.get("/api/v1/audit-logs/").json()["results"]
    assert rows
    assert {row["organization"] for row in rows} == {str(world.org_a.pk)}
    assert client.get(f"/api/v1/audit-logs/{world.audit_b.pk}/").status_code == 404
    assert client.get("/api/v1/users/").status_code == 403


def test_a_key_is_not_a_person(world: World, client_for: ClientFactory) -> None:
    client = service(issue(world, client_for, ["users:read"])["key"])
    assert client.get("/api/v1/auth/me/").status_code in {401, 403}
    assert client.post("/api/v1/auth/logout-all/").status_code in {401, 403}
    assert client.get("/api/v1/auth/mfa/").status_code in {401, 403}


@pytest.mark.parametrize(
    "header",
    [
        "ApiKey mtk_000000000000_wrong",
        "ApiKey mtk_a0000000000a_wrong-secret",  # world's real prefix, wrong secret
        "ApiKey mtk_short_x",
        "ApiKey not-a-key",
        "ApiKey",
        "ApiKey two parts",
        "ApiKey mtk_a0000000000a_",
    ],
)
def test_invalid_keys_all_look_the_same(world: World, header: str) -> None:
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=header)
    response = client.get("/api/v1/audit-logs/")
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid API key."}


def test_the_world_fixture_key_works_with_its_secret(world: World) -> None:
    response = service("mtk_a0000000000a_secret-a").get("/api/v1/audit-logs/")
    assert response.status_code == 200


@pytest.mark.parametrize("state", ["revoked", "expired", "organization-inactive"])
def test_dead_keys_are_refused(world: World, client_for: ClientFactory, state: str) -> None:
    body = issue(world, client_for, ["users:read"])
    match state:
        case "revoked":
            client_for(world.admin_a).post(f"{KEYS}{body['id']}/revoke/")
        case "expired":
            ApiKey.objects.filter(pk=body["id"]).update(expires_at=timezone.now())
        case "organization-inactive":
            Organization.objects.filter(pk=world.org_a.pk).update(is_active=False)
    response = service(body["key"]).get("/api/v1/users/")
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid API key."}


def test_last_use_is_recorded_at_most_once_a_minute(
    world: World, client_for: ClientFactory
) -> None:
    body = issue(world, client_for, ["users:read"])
    client = service(body["key"])
    client.get("/api/v1/users/", REMOTE_ADDR="198.51.100.20")
    key = ApiKey.objects.get(pk=body["id"])
    first = key.last_used_at
    assert (first is not None, key.last_used_ip) == (True, "198.51.100.20")
    client.get("/api/v1/users/", REMOTE_ADDR="198.51.100.21")
    key.refresh_from_db()
    assert (key.last_used_at, key.last_used_ip) == (first, "198.51.100.20"), "no write"
    ApiKey.objects.filter(pk=key.pk).update(last_used_at=timezone.now() - timedelta(minutes=2))
    client.get("/api/v1/users/", REMOTE_ADDR="198.51.100.21")
    key.refresh_from_db()
    assert key.last_used_ip == "198.51.100.21"


def test_each_key_is_its_own_throttle_identity(world: World, client_for: ClientFactory) -> None:
    body = issue(world, client_for, ["users:read"])
    service(body["key"]).get("/api/v1/users/")
    assert cache.get(f"throttle_user_apikey:{body['id']}") is not None


# ---------------------------------------------------------------- rotation and revocation
def test_rotation_with_no_grace_cuts_the_old_key_off(
    world: World, client_for: ClientFactory
) -> None:
    old = issue(world, client_for, ["users:read"])
    rotated = client_for(world.admin_a).post(f"{KEYS}{old['id']}/rotate/", {"grace_minutes": 0})
    assert rotated.status_code == 201
    new = rotated.json()
    assert (new["name"], new["scopes"], new["rotated_from"]) == (
        old["name"],
        old["scopes"],
        old["id"],
    )
    assert new["key"] != old["key"]
    assert service(old["key"]).get("/api/v1/users/").status_code == 401
    assert service(new["key"]).get("/api/v1/users/").status_code == 200
    event = AuditLog.objects.get(action=AuditAction.API_KEY_ROTATED)
    assert event.metadata["grace_minutes"] == 0


def test_rotation_with_grace_keeps_the_old_key_for_a_while(
    world: World, client_for: ClientFactory
) -> None:
    old = issue(world, client_for, ["users:read"])
    new = client_for(world.admin_a).post(f"{KEYS}{old['id']}/rotate/", {"grace_minutes": 30}).json()
    assert service(old["key"]).get("/api/v1/users/").status_code == 200
    assert service(new["key"]).get("/api/v1/users/").status_code == 200
    stored = ApiKey.objects.get(pk=old["id"])
    assert stored.expires_at <= timezone.now() + timedelta(minutes=30)
    ApiKey.objects.filter(pk=old["id"]).update(expires_at=timezone.now())
    assert service(old["key"]).get("/api/v1/users/").status_code == 401


def test_only_active_keys_can_be_rotated_or_revoked(
    world: World, client_for: ClientFactory
) -> None:
    body = issue(world, client_for, ["users:read"])
    admin = client_for(world.admin_a)
    assert admin.post(f"{KEYS}{body['id']}/revoke/").status_code == 200
    assert admin.post(f"{KEYS}{body['id']}/revoke/").status_code == 400
    assert admin.post(f"{KEYS}{body['id']}/rotate/").status_code == 400
    assert admin.post(f"{KEYS}{body['id']}/rotate/", {"grace_minutes": 5000}).status_code == 400
    assert AuditLog.objects.filter(action=AuditAction.API_KEY_REVOKED).count() == 1


# ---------------------------------------------------------------- structure
def test_api_keys_are_only_ever_granted_read_actions() -> None:
    for prefix, viewset, _basename in router.registry:
        scopes = getattr(viewset, "api_key_scopes", {})
        assert set(scopes) <= {"list", "retrieve"}, f"{prefix}: keys are read-only"


@pytest.mark.skipif(not POSTGRES, reason="row-level security is PostgreSQL-only")
def test_with_application_scoping_off_a_key_still_sees_only_its_tenant(
    world: World, client_for: ClientFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = issue(world, client_for, ["users:read"])["key"]
    monkeypatch.setattr(TenantQuerySet, "visible_to", lambda self, candidate: self.all())
    monkeypatch.setattr(TenantObjectPermission, "has_object_permission", lambda *a: True)
    client = service(key)
    users = client.get("/api/v1/users/", {"page_size": 100}).json()["results"]
    assert {row["organization"] for row in users} == {str(world.org_a.pk)}
    assert client.get(f"/api/v1/users/{world.admin_b.pk}/").status_code == 404
