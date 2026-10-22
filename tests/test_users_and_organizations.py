from __future__ import annotations

import pytest
from django.db import IntegrityError, transaction
from django.urls import reverse

from apps.accounts.models import User
from apps.accounts.roles import Role
from apps.auditlogs.models import AuditAction, AuditLog
from apps.organizations.models import Organization
from tests.conftest import ClientFactory, World, make_user

pytestmark = pytest.mark.django_db


# ---------------------------------------------------------------- users
def test_role_change_is_audited_with_before_and_after(
    world: World, client_for: ClientFactory
) -> None:
    response = client_for(world.admin_a).patch(
        reverse("user-detail", args=[world.member_a.pk]), {"role": "ORG_ADMIN"}
    )
    assert response.status_code == 200
    assert response.json()["role"] == "ORG_ADMIN"
    event = AuditLog.objects.filter(
        action=AuditAction.USER_ROLE_CHANGED, target_id=str(world.member_a.pk)
    ).latest("created_at")
    assert event.metadata == {"from": "MEMBER", "to": "ORG_ADMIN"}
    assert event.actor == world.admin_a
    assert event.organization == world.org_a


def test_soft_deactivation_and_reactivation(world: World, client_for: ClientFactory) -> None:
    client = client_for(world.admin_a)
    deactivated = client.post(reverse("user-deactivate", args=[world.member_a.pk])).json()
    assert deactivated["is_active"] is False
    assert deactivated["deactivated_at"] is not None
    assert User.objects.filter(pk=world.member_a.pk).exists()  # soft, not deleted

    # Idempotent: no duplicate audit event.
    client.post(reverse("user-deactivate", args=[world.member_a.pk]))
    assert AuditLog.objects.filter(action=AuditAction.USER_DEACTIVATED).count() == 1

    reactivated = client.post(reverse("user-reactivate", args=[world.member_a.pk])).json()
    assert reactivated["is_active"] is True
    assert reactivated["deactivated_at"] is None
    client.post(reverse("user-reactivate", args=[world.member_a.pk]))
    assert AuditLog.objects.filter(action=AuditAction.USER_REACTIVATED).count() == 1


def test_admin_can_be_demoted_when_another_admin_remains(
    world: World, client_for: ClientFactory
) -> None:
    second = make_user("admin2@a.test", Role.ORG_ADMIN, world.org_a)
    response = client_for(second).patch(
        reverse("user-detail", args=[world.admin_a.pk]), {"role": "MEMBER"}
    )
    assert response.status_code == 200
    # ...but now `second` is the last admin and cannot be removed by a super admin.
    response = client_for(world.super_admin).post(reverse("user-deactivate", args=[second.pk]))
    assert response.status_code == 400


def test_role_change_to_same_role_is_a_noop(world: World, client_for: ClientFactory) -> None:
    before = AuditLog.objects.count()
    response = client_for(world.admin_a).patch(
        reverse("user-detail", args=[world.member_a.pk]), {"role": "MEMBER"}
    )
    assert response.status_code == 200
    assert AuditLog.objects.count() == before


@pytest.mark.parametrize("method", ["put", "delete"])
def test_users_cannot_be_replaced_or_hard_deleted(
    world: World, client_for: ClientFactory, method: str
) -> None:
    response = getattr(client_for(world.super_admin), method)(
        reverse("user-detail", args=[world.member_a.pk]), {}
    )
    assert response.status_code == 405
    assert User.objects.filter(pk=world.member_a.pk).exists()


def test_user_filters_and_search(world: World, client_for: ClientFactory) -> None:
    client = client_for(world.admin_a)

    def emails(**params: str) -> set[str]:
        return {row["email"] for row in client.get(reverse("user-list"), params).json()["results"]}

    assert emails(role="ORG_ADMIN") == {"admin@a.test"}
    assert emails(is_active="false") == {"former@a.test"}
    assert emails(search="member") == {"member@a.test"}


def test_pagination_shape(world: World, client_for: ClientFactory) -> None:
    body = client_for(world.super_admin).get(reverse("user-list"), {"page_size": 2}).json()
    assert body["count"] == User.objects.count()
    assert len(body["results"]) == 2
    assert body["next"] is not None


def test_malformed_ids_are_404(world: World, client_for: ClientFactory) -> None:
    assert client_for(world.admin_a).get("/api/v1/users/not-a-uuid/").status_code == 404


# ---------------------------------------------------------------- organizations
def test_super_admin_creates_organization_with_generated_slug(
    world: World, client_for: ClientFactory
) -> None:
    client = client_for(world.super_admin)
    first = client.post(reverse("organization-list"), {"name": "Acme Labs"})
    assert first.status_code == 201
    assert first.json()["slug"] == "acme-labs"
    assert first.json()["member_count"] == 0

    Organization.objects.filter(slug="acme-labs").update(name="Renamed")
    second = client.post(reverse("organization-list"), {"name": "Acme Labs"})
    assert second.json()["slug"] == "acme-labs-2"
    assert AuditLog.objects.filter(action=AuditAction.ORGANIZATION_CREATED).count() == 2


@pytest.mark.parametrize("payload", [{"name": "ACME corp"}, {"name": "New", "slug": "globex"}])
def test_organization_uniqueness(
    world: World, client_for: ClientFactory, payload: dict[str, str]
) -> None:
    response = client_for(world.super_admin).post(reverse("organization-list"), payload)
    assert response.status_code == 400


def test_organization_update_is_audited_as_a_diff(world: World, client_for: ClientFactory) -> None:
    response = client_for(world.super_admin).patch(
        reverse("organization-detail", args=[world.org_b.pk]), {"is_active": False}
    )
    assert response.status_code == 200
    assert response.json()["is_active"] is False
    event = AuditLog.objects.get(action=AuditAction.ORGANIZATION_UPDATED)
    assert event.metadata == {"changes": {"is_active": {"from": True, "to": False}}}


def test_member_count_counts_active_members(world: World, client_for: ClientFactory) -> None:
    body = client_for(world.member_a).get(reverse("organization-detail", args=[world.org_a.pk]))
    assert body.json()["member_count"] == 2


# ---------------------------------------------------------------- model invariants
@pytest.mark.parametrize(
    "fields",
    [
        {"role": Role.MEMBER, "organization": None},
        {"role": Role.ORG_ADMIN, "organization": None},
        {"role": Role.SUPER_ADMIN, "organization": "org"},
        {"role": Role.MEMBER, "organization": "org", "is_staff": True},
        {"role": Role.ORG_ADMIN, "organization": "org", "is_superuser": True},
    ],
)
def test_database_enforces_tenancy_invariants(world: World, fields: dict[str, object]) -> None:
    values = {k: world.org_a if v == "org" else v for k, v in fields.items()}
    with pytest.raises(IntegrityError), transaction.atomic():
        User.objects.create_user("bad@a.test", "x", **values)


def test_emails_are_normalized(world: World) -> None:
    user = User.objects.create_user("  MiXeD@A.Test ", "x", organization=world.org_a)
    assert user.email == "mixed@a.test"
    assert User.objects.get_by_natural_key("MIXED@a.test") == user


def test_create_user_requires_email() -> None:
    with pytest.raises(ValueError, match="Email"):
        User.objects.create_user("", "x")
