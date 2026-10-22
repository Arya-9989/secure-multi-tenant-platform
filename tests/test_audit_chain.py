"""Audit log integrity, partitioning, retention and SIEM streaming (ADR 0006).

Tampering is done the way someone with database access would: raw SQL as the
schema owner, with the append-only trigger and row-level security switched off
(on SQLite there is neither). Verification must find every change and say which
row it was.
"""

from __future__ import annotations

import hashlib
import hmac
import http.server
import io
import itertools
import json
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError, connection, connections
from django.test import override_settings
from django.utils import timezone

from apps.auditlogs import chain, partitions, siem
from apps.auditlogs.models import (
    AuditAction,
    AuditChainCheckpoint,
    AuditExportCursor,
    AuditLog,
)
from apps.auditlogs.services import record
from apps.common.rls_migrations import runtime_role
from tests.conftest import POSTGRES, World, as_schema_owner

pytestmark = pytest.mark.django_db

PG_ONLY = pytest.mark.skipif(not POSTGRES, reason="PostgreSQL only")


def db_id(value: uuid.UUID) -> str:
    """A UUID as raw SQL must spell it (SQLite stores Django UUIDs as bare hex)."""
    return str(value) if POSTGRES else value.hex


def verify(*args: str) -> tuple[bool, str]:
    out = io.StringIO()
    try:
        call_command("verify_audit_chain", *args, stdout=out)
    except CommandError as exc:
        return False, out.getvalue() + str(exc)
    return True, out.getvalue()


@contextmanager
def database_access() -> Iterator[Any]:
    """A cursor that can rewrite the audit table; everything is undone afterwards."""
    if not POSTGRES:
        with connection.cursor() as cursor:
            yield cursor
        return
    with as_schema_owner(), connection.cursor() as cursor:
        cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cursor.execute(
            "ALTER TABLE auditlogs_auditlog DISABLE TRIGGER auditlogs_auditlog_append_only"
        )
        cursor.execute("ALTER TABLE auditlogs_auditlog NO FORCE ROW LEVEL SECURITY")
        yield cursor


def acme_events(world: World, count: int = 4) -> list[AuditLog]:
    return [world.audit_a] + [
        record(AuditAction.LOGOUT, actor=world.member_a, organization=world.org_a)
        for _ in range(count - 1)
    ]


# ---------------------------------------------------------------- the chain
def test_every_tenant_has_its_own_chain(world: World) -> None:
    events = acme_events(world)
    platform = record(AuditAction.LOGIN_FAILED, metadata={"email": "x@y.test"})
    assert [e.chain_seq for e in events] == [1, 2, 3, 4]
    assert events[0].prev_hash == chain.GENESIS
    assert all(b.prev_hash == a.hash for a, b in itertools.pairwise(events))
    assert world.audit_b.chain_seq == 1, "Globex's chain is independent"
    assert (platform.chain_seq, platform.prev_hash) == (1, chain.GENESIS)
    stored = AuditLog.objects.filter(pk=events[2].pk).values(*chain.HASHED_FIELDS, "hash").get()
    assert chain.compute_hash(stored) == stored["hash"], "what is read back hashes the same"


def test_metadata_is_stored_exactly_as_it_was_hashed(world: World) -> None:
    entry = record(
        AuditAction.LOGOUT,
        organization=world.org_a,
        metadata={"when": timezone.now(), "id": world.org_a.pk, "nested": {"b": 1.5, "a": [1]}},
    )
    stored = AuditLog.objects.filter(pk=entry.pk).values(*chain.HASHED_FIELDS, "hash").get()
    assert chain.compute_hash(stored) == entry.hash


def test_time_never_runs_backwards_within_a_chain(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    head = record(AuditAction.LOGOUT, organization=world.org_a)
    monkeypatch.setattr(timezone, "now", lambda: head.created_at - timedelta(hours=1))
    later = record(AuditAction.LOGOUT, organization=world.org_a)
    assert later.created_at == head.created_at


def test_a_clean_log_verifies(world: World) -> None:
    acme_events(world)
    record(AuditAction.LOGIN_FAILED, metadata={"email": "x@y.test"})
    ok, output = verify()
    assert ok, output
    assert "Every audit chain verified." in output
    assert f"Acme Corp ({world.org_a.pk}): 4 event(s), head 4: OK" in output


# ---------------------------------------------------------------- tampering, detected
def test_a_modified_row_is_found(world: World) -> None:
    events = acme_events(world)
    with database_access() as cursor:
        cursor.execute(
            "UPDATE auditlogs_auditlog SET metadata = %s WHERE id = %s",
            ['{"from": "MEMBER", "to": "MEMBER"}', db_id(events[0].pk)],
        )
        ok, output = verify("--organization", str(world.org_a.pk))
    assert not ok
    assert "modified: row 1's content does not match its hash" in output
    assert str(events[0].pk) in output


def test_a_deleted_row_is_found(world: World) -> None:
    events = acme_events(world)
    with database_access() as cursor:
        cursor.execute("DELETE FROM auditlogs_auditlog WHERE id = %s", [db_id(events[1].pk)])
        ok, output = verify("--organization", str(world.org_a.pk))
    assert not ok
    assert "gap: sequence 2 missing (deleted rows)" in output


def test_reordered_rows_are_found(world: World) -> None:
    events = acme_events(world)
    with database_access() as cursor:
        cursor.execute(
            "UPDATE auditlogs_auditlog SET chain_seq = 99 WHERE id = %s", [db_id(events[1].pk)]
        )
        cursor.execute(
            "UPDATE auditlogs_auditlog SET chain_seq = 2 WHERE id = %s", [db_id(events[2].pk)]
        )
        cursor.execute(
            "UPDATE auditlogs_auditlog SET chain_seq = 3 WHERE id = %s", [db_id(events[1].pk)]
        )
        ok, output = verify("--organization", str(world.org_a.pk))
    assert not ok
    assert "relinked: row 2 does not follow row 1" in output
    assert "modified" in output


def test_a_forged_row_is_found(world: World) -> None:
    events = acme_events(world)
    forged: dict[str, Any] = {**AuditLog.objects.filter(pk=events[3].pk).values().get()}
    with database_access() as cursor:
        cursor.execute(
            "INSERT INTO auditlogs_auditlog (id, created_at, actor_email, action, target_type,"
            " target_id, metadata, user_agent, request_id, organization_id, chain_seq,"
            " prev_hash, hash) VALUES (%s, %s, '', 'auth.logout', '', '', '{}', '', '', %s,"
            " %s, %s, %s)",
            [
                db_id(uuid.UUID("11111111-1111-1111-1111-111111111111")),
                forged["created_at"] + timedelta(seconds=1),
                db_id(world.org_a.pk),
                5,
                events[3].hash,
                hashlib.sha256(b"a guess").hexdigest(),
            ],
        )
        ok, output = verify("--organization", str(world.org_a.pk))
    assert not ok
    assert "row 5's content does not match its hash" in output


def test_recomputing_hashes_without_the_key_does_not_help(world: World) -> None:
    """An attacker who edits a row and recomputes the chain with another key fails."""
    events = acme_events(world, count=2)
    with override_settings(AUDIT_CHAIN_KEY="the-attackers-guess-at-the-key"):
        values = AuditLog.objects.filter(pk=events[1].pk).values(*chain.HASHED_FIELDS).get()
        values["metadata"] = {"forged": True}
        recomputed = chain.compute_hash(values)
    with database_access() as cursor:
        cursor.execute(
            "UPDATE auditlogs_auditlog SET metadata = %s, hash = %s WHERE id = %s",
            ['{"forged": true}', recomputed, db_id(events[1].pk)],
        )
        ok, output = verify("--organization", str(world.org_a.pk))
    assert not ok
    assert "row 2's content does not match its hash" in output


def test_a_truncated_tail_is_found_against_the_siem_cursor(world: World) -> None:
    events = acme_events(world)
    AuditExportCursor.objects.create(chain=str(world.org_a.pk), last_seq=4)
    with database_access() as cursor:
        cursor.execute("DELETE FROM auditlogs_auditlog WHERE id = %s", [db_id(events[3].pk)])
        ok, output = verify("--organization", str(world.org_a.pk))
    assert not ok
    assert "truncated: the SIEM already received sequence 4, the table ends at 3" in output


def test_a_duplicated_sequence_number_is_found() -> None:
    rows = [
        {**dict.fromkeys(chain.HASHED_FIELDS, ""), "id": "a", "chain_seq": 1, "hash": "x"},
        {**dict.fromkeys(chain.HASHED_FIELDS, ""), "id": "b", "chain_seq": 1, "hash": "y"},
    ]
    for row in rows:
        row.update(metadata={}, created_at=datetime(2026, 1, 1, tzinfo=UTC), ip_address=None)
        row.update(organization_id=None, actor_id=None, prev_hash=chain.GENESIS)
    report = chain.verify_chain("platform", iter(rows))
    assert [f.kind for f in report.findings][-1] == "duplicate"


# ---------------------------------------------------------------- concurrency
@PG_ONLY
@pytest.mark.django_db(transaction=True)
def test_concurrent_writers_to_one_tenant_keep_a_gapless_chain(world: World) -> None:
    barrier = threading.Barrier(10)
    errors: list[BaseException] = []

    def write() -> None:
        try:
            barrier.wait(timeout=10)
            from apps.common import rls  # noqa: PLC0415

            with rls.tenant_scope(world.org_a.pk):
                record(AuditAction.LOGOUT, organization=world.org_a)
        except BaseException as exc:
            errors.append(exc)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=write) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert errors == []
    seqs = sorted(
        AuditLog.objects.filter(organization=world.org_a).values_list("chain_seq", flat=True)
    )
    assert seqs == list(range(1, 12))
    ok, output = verify("--organization", str(world.org_a.pk))
    assert ok, output


# ---------------------------------------------------------------- partitions, PostgreSQL only
@PG_ONLY
def test_the_audit_log_is_partitioned_by_month() -> None:
    assert partitions.is_partitioned(connection)
    names = {p.name for p in partitions.partitions(connection)}
    this_month = partitions.current_month()
    expected = {partitions.partition_name(partitions.add_months(this_month, n)) for n in range(13)}
    assert expected <= names


@PG_ONLY
def test_the_runtime_role_cannot_read_partitions_directly(world: World) -> None:
    """Everything goes through the parent, where the policies are."""
    name = partitions.partition_name(partitions.current_month())
    for table in (name, partitions.DEFAULT_PARTITION):
        with as_schema_owner(), connection.cursor() as cursor:
            cursor.execute(f"SET LOCAL ROLE {runtime_role()}")
            with pytest.raises(DatabaseError, match="permission denied"):
                cursor.execute(f"SELECT count(*) FROM {table}")  # noqa: S608


@PG_ONLY
def test_partitions_are_created_ahead_and_never_over_stranded_rows(world: World) -> None:
    far = partitions.add_months(partitions.current_month(), 30)
    with as_schema_owner():
        out = io.StringIO()
        call_command("audit_partitions", "--months-ahead", "13", stdout=out)
        assert "Created 1 partition(s)" in out.getvalue()
        call_command("audit_partitions", "--months-ahead", "13", stdout=out)
        assert "Every partition already exists." in out.getvalue()
        with connection.cursor() as cursor:  # a row nobody made a partition for
            cursor.execute("ALTER TABLE auditlogs_auditlog NO FORCE ROW LEVEL SECURITY")
        record_at(world, datetime(far.year, far.month, 2, tzinfo=UTC))
        with pytest.raises(partitions.PartitionError, match="default partition"):
            partitions.ensure_partition(connection, far)
        with pytest.raises(CommandError, match="between 0 and 36"):
            call_command("audit_partitions", "--months-ahead", "99")


def owner_delete(where: str, params: list[Any]) -> None:
    """As the owner, with the trigger and FORCE off just for this statement."""
    with connection.cursor() as cursor:
        cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cursor.execute(
            "ALTER TABLE auditlogs_auditlog DISABLE TRIGGER auditlogs_auditlog_append_only"
        )
        cursor.execute("ALTER TABLE auditlogs_auditlog NO FORCE ROW LEVEL SECURITY")
        cursor.execute(f"DELETE FROM auditlogs_auditlog WHERE {where}", params)  # noqa: S608
        cursor.execute("ALTER TABLE auditlogs_auditlog FORCE ROW LEVEL SECURITY")
        cursor.execute(
            "ALTER TABLE auditlogs_auditlog ENABLE TRIGGER auditlogs_auditlog_append_only"
        )


def record_at(world: World, moment: datetime, organization: Any = None) -> AuditLog:
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(timezone, "now", lambda: moment)
        return record(AuditAction.LOGOUT, organization=organization or world.org_a)


@PG_ONLY
def test_retention_drops_old_months_and_the_chain_still_verifies(world: World) -> None:
    this_month = partitions.current_month()
    old = partitions.add_months(this_month, -3)
    with as_schema_owner():
        partitions.ensure_partition(connection, old)
        # Rebuild Acme's chain so that it starts three months ago.
        owner_delete("organization_id = %s", [db_id(world.org_a.pk)])
        start = datetime(old.year, old.month, 5, tzinfo=UTC)
        for day in range(3):
            record_at(world, start + timedelta(days=day))
        recent = [record(AuditAction.LOGOUT, organization=world.org_a) for _ in range(2)]

        dry = io.StringIO()
        call_command("audit_retention", "--keep-months", "2", "--dry-run", stdout=dry)
        assert f"Would drop {partitions.partition_name(old)}: 3 event(s)." in dry.getvalue()
        assert AuditLog.objects.filter(organization=world.org_a).count() == 5

        out = io.StringIO()
        call_command("audit_retention", "--keep-months", "2", stdout=out)
        assert (
            f"Dropped {partitions.partition_name(old)}: 3 event(s), 1 chain(s)." in out.getvalue()
        )
        assert (
            list(AuditLog.objects.filter(organization=world.org_a).order_by("chain_seq")) == recent
        )
        checkpoint = AuditChainCheckpoint.objects.get(organization=world.org_a)
        assert (checkpoint.chain_seq, checkpoint.hash) == (3, recent[0].prev_hash)
        assert AuditLog.objects.filter(action=AuditAction.AUDIT_RETENTION_APPLIED).exists()
        ok, output = verify("--organization", str(world.org_a.pk))
        assert ok, output
        # A deletion right after the cut is still a deletion.
        owner_delete("id = %s", [db_id(recent[0].pk)])
        ok, output = verify("--organization", str(world.org_a.pk))
        assert not ok
        assert "gap: sequence 4 missing" in output
    nothing = io.StringIO()
    with as_schema_owner():
        call_command("audit_retention", "--keep-months", "120", stdout=nothing)
    assert "Nothing older than" in nothing.getvalue()


@PG_ONLY
def test_after_retention_a_chain_restarts_from_its_checkpoint(world: World) -> None:
    AuditChainCheckpoint.objects.create(
        organization=None,
        chain_seq=41,
        hash="f" * 64,
        last_created_at=timezone.now(),
        partition="auditlogs_auditlog_p202401",
    )
    entry = record(AuditAction.LOGIN_FAILED, metadata={"email": "x@y.test"})
    assert (entry.chain_seq, entry.prev_hash) == (42, "f" * 64)
    ok, output = verify("--platform")
    assert ok, output


def test_retention_and_partitions_need_postgresql_partitioning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(partitions, "is_partitioned", lambda connection: False)
    for command in (("audit_partitions",), ("audit_retention", "--keep-months", "1")):
        with pytest.raises(CommandError):
            call_command(*command)
    monkeypatch.setattr(partitions, "is_partitioned", lambda connection: True)
    with pytest.raises(CommandError, match="at least 1"):
        call_command("audit_retention", "--keep-months", "0")


# ---------------------------------------------------------------- SIEM streaming
class _Siem(http.server.BaseHTTPRequestHandler):
    received: list[dict[str, Any]] = []
    failures_left = 0

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        if type(self).failures_left > 0:
            type(self).failures_left -= 1
            self.send_response(503)
            self.end_headers()
            return
        type(self).received.append(
            {
                "body": body,
                "signature": self.headers["X-Audit-Signature"],
                "batch": self.headers["X-Audit-Batch"],
                "type": self.headers["Content-Type"],
            }
        )
        self.send_response(202)
        self.end_headers()

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def siem_server() -> Iterator[type[_Siem]]:
    _Siem.received, _Siem.failures_left = [], 0
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Siem)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    with override_settings(
        AUDIT_SIEM_URL=f"http://127.0.0.1:{server.server_address[1]}/audit",
        AUDIT_SIEM_SECRET="siem-shared-secret",
        AUDIT_SIEM_BATCH_SIZE=2,
        AUDIT_SIEM_MAX_ATTEMPTS=3,
    ):
        yield _Siem
    server.shutdown()


def shipped_events(server: type[_Siem]) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for request in server.received
        for line in request["body"].decode().splitlines()
    ]


def test_events_stream_in_order_signed_and_resume(world: World, siem_server: type[_Siem]) -> None:
    acme_events(world)
    out = io.StringIO()
    call_command("stream_audit_log", "--once", stdout=out)
    assert "Shipped 5 event(s) in 3 batch(es)." in out.getvalue()  # Acme 2+2, Globex 1

    for request in siem_server.received:
        expected = (
            "sha256=" + hmac.new(b"siem-shared-secret", request["body"], hashlib.sha256).hexdigest()
        )
        assert request["signature"] == expected
        assert request["type"] == "application/x-ndjson"
    events = shipped_events(siem_server)
    acme = [e for e in events if e["chain"] == str(world.org_a.pk)]
    assert [e["seq"] for e in acme] == [1, 2, 3, 4]
    assert all(b["prev_hash"] == a["hash"] for a, b in itertools.pairwise(acme))
    assert {"id", "hash", "action", "created_at", "metadata"} <= set(acme[0])
    assert AuditExportCursor.objects.get(chain=str(world.org_a.pk)).last_seq == 4

    call_command("stream_audit_log", "--once", stdout=out)
    assert len(shipped_events(siem_server)) == 5, "nothing twice"
    record(AuditAction.LOGOUT, organization=world.org_b)
    call_command("stream_audit_log", "--once", stdout=out)
    assert [e["seq"] for e in shipped_events(siem_server)[5:]] == [2]


def test_a_failing_siem_is_retried_and_nothing_is_skipped(
    world: World, siem_server: type[_Siem], monkeypatch: pytest.MonkeyPatch
) -> None:
    pauses: list[float] = []
    monkeypatch.setattr("apps.auditlogs.siem.time.sleep", pauses.append)
    siem_server.failures_left = 2  # then it recovers
    call_command("stream_audit_log", "--once", stdout=io.StringIO())
    assert len(pauses) == 2
    assert pauses[0] < pauses[1] * 2, "backoff grows"
    assert len(shipped_events(siem_server)) == 2

    siem_server.failures_left = 99
    record(AuditAction.LOGOUT, organization=world.org_a)
    with pytest.raises(CommandError, match="did not accept"):
        call_command("stream_audit_log", "--once", stdout=io.StringIO())
    assert AuditExportCursor.objects.get(chain=str(world.org_a.pk)).last_seq == 1, "not advanced"


def test_streaming_needs_a_destination(world: World) -> None:
    with pytest.raises(CommandError, match="AUDIT_SIEM_URL"):
        call_command("stream_audit_log", "--once")


def test_the_streamer_keeps_going_after_a_failure_until_stopped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StopOnSecondWait:
        def __init__(self) -> None:
            self.waits = 0

        def set(self) -> None:  # pragma: no cover - only a signal calls it
            pass

        def wait(self, timeout: float | None = None) -> bool:
            self.waits += 1
            return self.waits >= 2

    outcomes: list[Any] = [siem.SiemDeliveryError("down"), siem.ShipResult(3, 1)]

    def ship(**kwargs: Any) -> siem.ShipResult:
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        assert isinstance(outcome, siem.ShipResult)
        return outcome

    monkeypatch.setattr(
        "apps.auditlogs.management.commands.stream_audit_log.threading.Event", StopOnSecondWait
    )
    monkeypatch.setattr(siem, "ship_once", ship)
    out, err = io.StringIO(), io.StringIO()
    call_command("stream_audit_log", "--interval", "0", stdout=out, stderr=err)
    assert "down; retrying" in err.getvalue()
    assert "Shipped 3 event(s) in 1 batch(es)." in out.getvalue()
