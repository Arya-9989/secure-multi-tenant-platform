"""Background tasks and asynchronous invitation email (ADR 0007).

The queue is Django's task API on a database backend: transactional enqueue,
tenant scope carried to the worker, retries with backoff, leases, deduplication.
The invitation email on top of it is idempotent and records its delivery.
"""

from __future__ import annotations

import io
import re
import threading
from datetime import timedelta
from typing import Any

import pytest
from django.core import mail
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connections, transaction
from django.tasks.exceptions import TaskResultDoesNotExist
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.models import EmailStatus, Invitation
from apps.auditlogs.models import AuditAction, AuditLog
from apps.common import rls
from apps.tasks import worker
from apps.tasks.models import TaskRecord, TaskStatus
from tests import task_fixtures
from tests.conftest import POSTGRES, ClientFactory, World

pytestmark = pytest.mark.django_db

ACCEPT = "/api/v1/invitations/accept/"


@pytest.fixture(autouse=True)
def _fresh_calls() -> None:
    task_fixtures.CALLS.clear()


def make_ready(record_filter: dict[str, Any] | None = None) -> None:
    """Pretend the backoff has passed."""
    TaskRecord.objects.filter(**(record_filter or {})).update(run_after=timezone.now())


# ---------------------------------------------------------------- the queue
def _enqueue_then_fail() -> None:
    with transaction.atomic():
        task_fixtures.remember.enqueue("lost")
        raise ZeroDivisionError


def test_enqueue_commits_or_rolls_back_with_the_change() -> None:
    with pytest.raises(ZeroDivisionError):
        _enqueue_then_fail()
    assert not TaskRecord.objects.exists()
    result = task_fixtures.remember.enqueue("kept")
    assert result.status == "READY"
    assert worker.drain() == 1
    assert task_fixtures.CALLS == ["kept"]
    done = task_fixtures.remember.get_result(result.id)
    assert (done.status, done.return_value, done.attempts) == ("SUCCESSFUL", "KEPT", 1)


def test_an_identical_task_is_queued_once_while_pending() -> None:
    first = task_fixtures.remember.enqueue("same")
    second = task_fixtures.remember.enqueue("same")
    assert first.id == second.id
    assert TaskRecord.objects.count() == 1
    worker.drain()
    third = task_fixtures.remember.enqueue("same")
    assert third.id != first.id, "once done, the same task can run again"


def test_tasks_run_in_the_scope_they_were_queued_under(world: World) -> None:
    with rls.tenant_scope(world.org_a.pk):
        tenant = task_fixtures.count_visible_users.enqueue()
    with rls.platform_scope():
        platform = task_fixtures.count_visible_users.enqueue()
    record = TaskRecord.objects.get(pk=tenant.id)
    assert (record.organization_id, record.platform_scope) == (world.org_a.pk, False)
    worker.drain()
    seen = task_fixtures.count_visible_users.get_result(tenant.id).return_value
    everything = task_fixtures.count_visible_users.get_result(platform.id).return_value
    if POSTGRES:  # row-level security decides what the task can see
        assert (seen, everything) == (3, 7)
    else:
        assert everything == 7


@pytest.mark.skipif(not POSTGRES, reason="row-level security is PostgreSQL-only")
def test_a_task_cannot_be_queued_without_a_scope() -> None:
    with (
        rls.scope(rls.NO_SCOPE),
        pytest.raises(Exception, match="row-level security"),
        transaction.atomic(),
    ):
        task_fixtures.remember.enqueue("nowhere")


def test_failures_are_retried_with_backoff_then_fail_for_good() -> None:
    result = task_fixtures.always_fails.enqueue()
    for attempt in range(1, 6):
        make_ready()
        assert worker.run_once() == [TaskStatus.READY if attempt < 5 else TaskStatus.FAILED], (
            attempt
        )
        record = TaskRecord.objects.get(pk=result.id)
        if attempt < 5:
            assert record.run_after > timezone.now(), "not before its backoff"
            assert worker.run_once() == [], "nothing ready yet"
    record = TaskRecord.objects.get(pk=result.id)
    assert (record.status, record.attempts) == (TaskStatus.FAILED, 5)
    assert record.errors[-1]["exception_class_path"] == "builtins.ConnectionError"
    assert "downstream is down" in record.errors[-1]["traceback"]
    failed = task_fixtures.always_fails.get_result(result.id)
    assert failed.status == "FAILED"
    assert len(failed.errors) == 5


def test_a_permanent_error_is_not_retried() -> None:
    result = task_fixtures.fails_for_good.enqueue()
    assert worker.run_once() == [TaskStatus.FAILED]
    assert TaskRecord.objects.get(pk=result.id).attempts == 1


@pytest.mark.parametrize("attempt", [1, 2, 5, 12, 40])
def test_backoff_doubles_with_jitter_and_is_capped(attempt: int) -> None:
    options = worker.backend().options
    delay = worker.backoff(attempt, options).total_seconds()
    nominal = min(options["max_delay"], options["base_delay"] * 2 ** (attempt - 1))
    assert nominal * 0.5 <= delay <= nominal * 1.5


def test_a_task_whose_worker_died_is_picked_up_again() -> None:
    result = task_fixtures.remember.enqueue("orphan")
    (claimed,) = worker.claim("dead-worker")
    assert worker.claim("other-worker") == [], "leased"
    TaskRecord.objects.filter(pk=claimed.pk).update(leased_until=timezone.now() - timedelta(1))
    (again,) = worker.claim("rescuer")
    assert again.attempts == 2
    assert again.worker_ids == ["dead-worker", "rescuer"]
    worker.execute(again)
    assert task_fixtures.remember.get_result(result.id).status == "SUCCESSFUL"


def test_priority_and_deferral() -> None:
    later = task_fixtures.remember.using(run_after=timezone.now() + timedelta(hours=1))
    later.enqueue("later")
    task_fixtures.remember.enqueue("normal")
    task_fixtures.urgent.enqueue("first")
    worker.drain()
    assert task_fixtures.CALLS == ["urgent:first", "normal"]


def test_unknown_results_are_reported() -> None:
    with pytest.raises(TaskResultDoesNotExist):
        task_fixtures.remember.get_result("00000000-0000-0000-0000-000000000000")


@pytest.mark.skipif(not POSTGRES, reason="needs SKIP LOCKED and concurrent connections")
@pytest.mark.django_db(transaction=True)
def test_concurrent_workers_never_claim_the_same_task() -> None:
    with rls.platform_scope():
        for n in range(30):
            task_fixtures.remember.enqueue(f"job-{n}")
    barrier = threading.Barrier(4)
    claimed: list[str] = []
    lock = threading.Lock()

    def claim(name: str) -> None:
        try:
            barrier.wait(timeout=10)
            records = worker.claim(name, limit=10)
            with lock:
                claimed.extend(str(r.pk) for r in records)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=claim, args=(f"w{n}",)) for n in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert len(claimed) == len(set(claimed)) == 30


def test_the_worker_and_prune_commands() -> None:
    task_fixtures.remember.enqueue("cli")
    out = io.StringIO()
    call_command("run_worker", "--once", stdout=out)
    assert "Ran 1 task(s): SUCCESSFUL" in out.getvalue()
    TaskRecord.objects.update(finished_at=timezone.now() - timedelta(days=8))
    task_fixtures.remember.enqueue("pending")
    call_command("prune_tasks", "--days", "7", stdout=out)
    assert "Deleted 1 finished task(s)." in out.getvalue()
    assert TaskRecord.objects.get().status == TaskStatus.READY, "pending tasks stay"
    with pytest.raises(CommandError):
        call_command("prune_tasks", "--days", "-1")


def test_the_worker_touches_its_heartbeat_after_each_poll(tmp_path: Any) -> None:
    heartbeat = tmp_path / "worker-heartbeat"
    call_command("run_worker", "--once", "--heartbeat", str(heartbeat), stdout=io.StringIO())
    assert heartbeat.exists(), "an idle poll still proves the worker reached the database"


# ---------------------------------------------------------------- invitation email
def invite(world: World, client_for: ClientFactory, email: str = "carol@a.test") -> Any:
    response = client_for(world.admin_a).post(
        reverse("invitation-list"), {"email": email, "role": "MEMBER"}
    )
    assert response.status_code == 201, response.content
    return response.json()


def test_an_invitation_email_is_queued_with_the_invitation_and_delivered(
    world: World, client_for: ClientFactory
) -> None:
    body = invite(world, client_for)
    record = TaskRecord.objects.get()
    assert record.task_path == "apps.accounts.tasks.send_invitation_email"
    assert record.organization_id == world.org_a.pk, "runs in the invitation's tenant"
    assert body["token"] not in str(record.args), "the token travels encrypted"
    worker.drain()
    (message,) = mail.outbox
    assert message.to == ["carol@a.test"]
    assert body["accept_url"] in message.body
    assert re.fullmatch(
        r"<invitation-[0-9a-f-]{36}-[0-9a-f]{16}@localhost>", message.extra_headers["Message-ID"]
    )
    invitation = Invitation.objects.get(pk=body["id"])
    assert (invitation.email_status, invitation.email_attempts) == (EmailStatus.SENT, 1)
    assert invitation.email_sent_at is not None
    detail = client_for(world.admin_a).get(reverse("invitation-detail", args=[body["id"]]))
    assert detail.json()["email_status"] == "sent"


def test_the_email_task_is_idempotent(world: World, client_for: ClientFactory) -> None:
    invite(world, client_for)
    record = TaskRecord.objects.get()
    worker.drain()
    TaskRecord.objects.filter(pk=record.pk).update(status=TaskStatus.READY)  # a duplicate run
    worker.drain()
    assert len(mail.outbox) == 1
    assert TaskRecord.objects.get(pk=record.pk).return_value == "already-sent"


def test_a_revoked_invitation_is_not_emailed(world: World, client_for: ClientFactory) -> None:
    body = invite(world, client_for)
    client_for(world.admin_a).post(reverse("invitation-revoke", args=[body["id"]]))
    worker.drain()
    assert mail.outbox == []
    assert Invitation.objects.get(pk=body["id"]).email_status == EmailStatus.SKIPPED


def test_a_failing_mail_server_is_retried_and_finally_marked_failed(
    world: World, client_for: ClientFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    def down(*args: Any, **kwargs: Any) -> None:
        raise TimeoutError("timed out")

    monkeypatch.setattr("django.core.mail.EmailMessage.send", down)
    body = invite(world, client_for)
    statuses = []
    for _ in range(5):
        make_ready()
        worker.run_once()
        statuses.append(Invitation.objects.get(pk=body["id"]).email_status)
    assert statuses == ["queued"] * 4 + ["failed"]
    invitation = Invitation.objects.get(pk=body["id"])
    assert (invitation.email_attempts, invitation.email_last_error) == (
        5,
        "TimeoutError: timed out",
    )
    assert invitation.status == "pending", "the invitation itself stays usable"


def test_resending_issues_a_new_link_and_kills_the_old_one(
    world: World, client_for: ClientFactory, api_client: APIClient
) -> None:
    first = invite(world, client_for)
    resent = client_for(world.admin_a).post(reverse("invitation-resend", args=[first["id"]]))
    assert resent.status_code == 200
    second = resent.json()
    assert second["token"] != first["token"]
    worker.drain()
    (message,) = mail.outbox  # the first task found its link superseded
    assert second["accept_url"] in message.body
    assert first["token"] not in message.body
    password = "Sturdy-Passphrase-42"
    assert (
        api_client.post(ACCEPT, {"token": first["token"], "password": password}).status_code == 400
    )
    assert (
        api_client.post(ACCEPT, {"token": second["token"], "password": password}).status_code == 201
    )
    assert AuditLog.objects.filter(action=AuditAction.INVITATION_RESENT).count() == 1


def test_only_pending_invitations_can_be_resent(world: World, client_for: ClientFactory) -> None:
    body = invite(world, client_for)
    admin = client_for(world.admin_a)
    admin.post(reverse("invitation-revoke", args=[body["id"]]))
    assert admin.post(reverse("invitation-resend", args=[body["id"]])).status_code == 400


def test_the_same_task_for_two_tenants_is_two_tasks(world: World) -> None:
    for organization in (world.org_a, world.org_b):
        with rls.tenant_scope(organization.pk):
            task_fixtures.count_visible_users.enqueue()
    assert TaskRecord.objects.count() == 2
