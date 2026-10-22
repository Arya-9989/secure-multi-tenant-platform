from __future__ import annotations

from datetime import timedelta

import pytest
from django.db import DatabaseError, connection, transaction
from django.db.models import ProtectedError
from django.urls import reverse
from django.utils import timezone

from apps.auditlogs.models import AuditAction, AuditLog, AuditLogImmutableError
from apps.auditlogs.services import record
from tests.conftest import ClientFactory, World

pytestmark = pytest.mark.django_db


# ---------------------------------------------------------------- immutability
def test_entries_cannot_be_updated_through_the_orm(world: World) -> None:
    entry = world.audit_a
    entry.action = AuditAction.LOGOUT
    with pytest.raises(AuditLogImmutableError):
        entry.save()
    with pytest.raises(AuditLogImmutableError):
        AuditLog.objects.filter(pk=entry.pk).update(action=AuditAction.LOGOUT)
    with pytest.raises(AuditLogImmutableError):
        AuditLog.objects.bulk_update([entry], ["action"])


def test_bulk_create_cannot_upsert_over_existing_entries(world: World) -> None:
    """``INSERT ... ON CONFLICT DO UPDATE`` is an update in disguise."""
    forged = AuditLog(id=world.audit_a.pk, action=AuditAction.LOGOUT, actor_email="x@evil.test")
    with pytest.raises(AuditLogImmutableError):
        AuditLog.objects.bulk_create(
            [forged], update_conflicts=True, unique_fields=["id"], update_fields=["action"]
        )
    assert AuditLog.objects.get(pk=world.audit_a.pk).action == AuditAction.USER_ROLE_CHANGED
    # Plain appends still work.
    assert len(AuditLog.objects.bulk_create([AuditLog(action=AuditAction.LOGOUT)])) == 1


def test_entries_cannot_be_deleted_through_the_orm(world: World) -> None:
    with pytest.raises(AuditLogImmutableError):
        world.audit_a.delete()
    with pytest.raises(AuditLogImmutableError):
        AuditLog.objects.all().delete()
    assert AuditLog.objects.filter(pk=world.audit_a.pk).exists()


@pytest.mark.skipif(connection.vendor != "postgresql", reason="trigger is PostgreSQL-only")
@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE auditlogs_auditlog SET action = 'tampered' WHERE id = %s",
        "DELETE FROM auditlogs_auditlog WHERE id = %s",
    ],
    ids=["update", "delete"],
)
def test_database_trigger_rejects_raw_sql_mutation(world: World, sql: str) -> None:
    with (
        pytest.raises(DatabaseError, match="append-only"),
        transaction.atomic(),
        connection.cursor() as cursor,
    ):
        cursor.execute(sql, [world.audit_a.pk])
    assert AuditLog.objects.get(pk=world.audit_a.pk).action == AuditAction.USER_ROLE_CHANGED


def test_actors_with_history_cannot_be_hard_deleted(world: World) -> None:
    with pytest.raises(ProtectedError):
        world.admin_a.delete()


def test_audit_endpoints_are_read_only(world: World, client_for: ClientFactory) -> None:
    client = client_for(world.super_admin)
    detail = reverse("auditlog-detail", args=[world.audit_a.pk])
    assert client.post(reverse("auditlog-list"), {}).status_code == 405
    assert client.patch(detail, {"action": "x"}).status_code == 405
    assert client.delete(detail).status_code == 405


# ---------------------------------------------------------------- content
def test_events_capture_who_what_tenant_ip_and_request_id(
    world: World, client_for: ClientFactory
) -> None:
    client_for(world.admin_a).post(
        reverse("user-deactivate", args=[world.member_a.pk]),
        HTTP_X_REQUEST_ID="trace-abc-123",
        HTTP_USER_AGENT="ops-console/1.0",
        REMOTE_ADDR="203.0.113.7",
    )
    event = AuditLog.objects.get(action=AuditAction.USER_DEACTIVATED)
    assert event.actor == world.admin_a
    assert event.actor_email == "admin@a.test"
    assert event.organization == world.org_a
    assert (event.target_type, event.target_id) == ("accounts.user", str(world.member_a.pk))
    assert event.ip_address == "203.0.113.7"
    assert event.user_agent == "ops-console/1.0"
    assert event.request_id == "trace-abc-123"


def test_record_outside_a_request_has_no_request_context(world: World) -> None:
    entry = record(AuditAction.LOGOUT, actor=world.member_a, organization=world.org_a)
    assert (entry.ip_address, entry.request_id, entry.user_agent) == (None, "", "")


# ---------------------------------------------------------------- querying
def test_org_admin_sees_only_own_tenant_and_super_admin_sees_platform_events(
    world: World, client_for: ClientFactory, api_client: object
) -> None:
    record(AuditAction.LOGIN_FAILED, metadata={"email": "nobody@x.test"})  # platform-level

    admin_rows = client_for(world.admin_a).get(reverse("auditlog-list")).json()["results"]
    assert {row["organization"] for row in admin_rows} == {str(world.org_a.pk)}

    root_rows = client_for(world.super_admin).get(reverse("auditlog-list")).json()["results"]
    assert None in {row["organization"] for row in root_rows}
    assert {str(world.org_a.pk), str(world.org_b.pk)} <= {row["organization"] for row in root_rows}


def test_filters(world: World, client_for: ClientFactory) -> None:
    record(AuditAction.LOGOUT, actor=world.member_a, organization=world.org_a)
    client = client_for(world.admin_a)
    url = reverse("auditlog-list")

    def actions(**params: str | list[str]) -> list[str]:
        return [row["action"] for row in client.get(url, params).json()["results"]]

    assert actions(action="auth.logout") == ["auth.logout"]
    assert sorted(actions(action=["auth.logout", "user.role_changed"])) == [
        "auth.logout",
        "user.role_changed",
    ]
    assert actions(actor=str(world.member_a.pk)) == ["auth.logout"]
    assert actions(target_id=str(world.member_a.pk)) == ["user.role_changed"]
    future = (timezone.now() + timedelta(hours=1)).isoformat()
    assert actions(created_after=future) == []
    assert len(actions(created_before=future)) == 2
    assert client.get(url, {"action": "not-a-real-action"}).status_code == 400


def test_cursor_pagination_is_newest_first_and_stable(
    world: World, client_for: ClientFactory
) -> None:
    for _ in range(5):
        record(AuditAction.LOGOUT, actor=world.member_a, organization=world.org_a)
    client = client_for(world.admin_a)
    page = client.get(reverse("auditlog-list"), {"page_size": 4}).json()
    assert set(page) == {"next", "previous", "results"}
    assert len(page["results"]) == 4
    timestamps = [row["created_at"] for row in page["results"]]
    assert timestamps == sorted(timestamps, reverse=True)

    second = client.get(page["next"]).json()
    seen = {row["id"] for row in page["results"]}
    assert len(second["results"]) == 2
    assert not seen & {row["id"] for row in second["results"]}
    assert second["next"] is None
