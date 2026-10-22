"""Running queued tasks (ADR 0007).

A worker claims a batch of ready tasks in a short platform-scoped transaction
(``SELECT ... FOR UPDATE SKIP LOCKED``, so workers never share a task) and
leases them. Each task then runs in the scope it was queued under. A failure is
retried with exponential backoff and jitter until ``max_attempts``; a task whose
worker died is claimed again once its lease runs out.
"""

from __future__ import annotations

import logging
import random
import secrets
import traceback
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from django.db import transaction
from django.db.models import Q
from django.tasks import TaskContext, task_backends
from django.tasks.signals import task_finished, task_started
from django.utils import timezone
from django.utils.json import normalize_json
from django.utils.module_loading import import_string

from apps.common import rls
from apps.tasks.backend import DatabaseBackend, PermanentTaskError, to_result
from apps.tasks.models import TaskRecord, TaskStatus

logger = logging.getLogger(__name__)

MAX_ERRORS_KEPT = 5


def backend() -> DatabaseBackend:
    configured = task_backends["default"]
    if not isinstance(configured, DatabaseBackend):  # pragma: no cover - configuration
        msg = "The worker needs apps.tasks.backend.DatabaseBackend as the default backend."
        raise TypeError(msg)
    return configured


def backoff(attempt: int, options: dict[str, Any]) -> timedelta:
    """Seconds before attempt ``attempt + 1``: doubling, capped, with +/-50% jitter."""
    delay = min(float(options["max_delay"]), float(options["base_delay"]) * 2 ** (attempt - 1))
    return timedelta(seconds=delay * (0.5 + random.random()))  # noqa: S311 - not crypto


def claim(worker_id: str, *, queue: str = "default", limit: int = 10) -> list[TaskRecord]:
    """Lease up to ``limit`` ready (or abandoned) tasks for this worker."""
    options = backend().options
    now = timezone.now()
    with rls.platform_scope(), transaction.atomic():
        records = list(
            TaskRecord.objects.select_for_update(skip_locked=True)
            .filter(queue_name=queue)
            .filter(
                Q(status=TaskStatus.READY, run_after__lte=now)
                | Q(status=TaskStatus.RUNNING, leased_until__lt=now)  # its worker died
            )
            .order_by("-priority", "run_after")[:limit]
        )
        for record in records:
            record.status = TaskStatus.RUNNING
            record.attempts += 1
            record.leased_until = now + timedelta(seconds=int(options["lease_seconds"]))
            record.started_at = record.started_at or now
            record.last_attempted_at = now
            record.worker_ids = [*record.worker_ids, worker_id]
            record.save()
    return records


def _scope_of(record: TaskRecord) -> rls.DbScope:
    return rls.PLATFORM if record.platform_scope else rls.for_tenant(record.organization_id)


def execute(record: TaskRecord) -> TaskStatus:
    """Run one claimed task in its own scope and store the outcome."""
    options = backend().options
    alias = backend().alias
    task = import_string(record.task_path)
    result = to_result(record, alias, task)
    task_started.send(type(backend()), task_result=result)
    try:
        with rls.scope(_scope_of(record)):
            if task.takes_context:
                value = task.call(TaskContext(task_result=result), *record.args, **record.kwargs)
            else:
                value = task.call(*record.args, **record.kwargs)
    except KeyboardInterrupt:
        raise
    except BaseException as exc:
        final = isinstance(exc, PermanentTaskError) or record.attempts >= int(
            options["max_attempts"]
        )
        record.errors = [
            *record.errors,
            {
                "exception_class_path": f"{type(exc).__module__}.{type(exc).__qualname__}",
                "traceback": "".join(traceback.format_exception(exc))[-4000:],
            },
        ][-MAX_ERRORS_KEPT:]
        record.leased_until = None
        if final:
            record.status, record.finished_at = TaskStatus.FAILED, timezone.now()
            logger.error("Task %s failed for good: %s", record.task_path, exc)
        else:
            record.status = TaskStatus.READY
            record.run_after = timezone.now() + backoff(record.attempts, options)
            logger.warning(
                "Task %s failed (attempt %s), retrying", record.task_path, record.attempts
            )
    else:
        record.status, record.finished_at = TaskStatus.SUCCESSFUL, timezone.now()
        record.return_value = normalize_json(value)
        record.leased_until = None
    with rls.platform_scope():
        record.save()
    if record.status != TaskStatus.READY:
        task_finished.send(type(backend()), task_result=to_result(record, alias, task))
    return TaskStatus(record.status)


def run_once(
    *, worker_id: str | None = None, queue: str = "default", limit: int = 10
) -> list[TaskStatus]:
    """Claim and run what is ready now; the statuses of what ran."""
    worker_id = worker_id or secrets.token_hex(8)
    return [execute(record) for record in claim(worker_id, queue=queue, limit=limit)]


def drain(*, queue: str = "default", until: Callable[[], bool] | None = None) -> int:
    """Run tasks until none is ready (tests and one-off jobs)."""
    ran = 0
    while (statuses := run_once(queue=queue)) and not (until and until()):
        ran += len(statuses)
    return ran
