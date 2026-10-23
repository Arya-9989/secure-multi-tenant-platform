"""A ``django.tasks`` backend that stores tasks in the database (ADR 0007).

``enqueue()`` inserts a row in the caller's transaction, so a task commits (or
rolls back) with the change that asked for it. The row remembers the database
scope it was queued under; the worker (:mod:`apps.tasks.worker`) runs it in that
scope. An identical task (same function, same arguments) is queued once while
it is pending.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from django.db import IntegrityError, transaction
from django.tasks import Task, TaskResult, TaskResultStatus
from django.tasks.backends.base import BaseTaskBackend
from django.tasks.base import TaskError
from django.tasks.exceptions import TaskResultDoesNotExist
from django.tasks.signals import task_enqueued
from django.utils import timezone
from django.utils.json import normalize_json
from django.utils.module_loading import import_string

from apps.common import rls, tracing
from apps.tasks.models import TaskRecord, TaskStatus

DEFAULT_OPTIONS: dict[str, Any] = {
    "max_attempts": 5,
    "base_delay": 10.0,
    "max_delay": 3600.0,
    "lease_seconds": 300,
}


class PermanentTaskError(Exception):
    """Raised by a task to fail at once, without retries."""


def dedupe_key(task_path: str, args: Any, kwargs: Any, scope: rls.DbScope) -> str:
    """The same function, arguments and scope: the same task (another tenant's is not)."""
    payload = json.dumps([task_path, args, kwargs, str(scope)], sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


class DatabaseBackend(BaseTaskBackend):
    supports_defer = True
    supports_get_result = True
    supports_priority = True

    def __init__(self, alias: str, params: dict[str, Any]) -> None:
        super().__init__(alias, params)
        self.options = {**DEFAULT_OPTIONS, **params.get("OPTIONS", {})}

    def enqueue(  # type: ignore[override]
        self, task: Task[..., Any], args: Any, kwargs: Any
    ) -> TaskResult[..., Any]:
        self.validate_task(task)
        args, kwargs = normalize_json(list(args)), normalize_json(dict(kwargs))
        scope = rls.current_scope()
        key = dedupe_key(task.module_path, args, kwargs, scope)
        fields = {
            "task_path": task.module_path,
            "queue_name": task.queue_name,
            "priority": task.priority,
            "args": args,
            "kwargs": kwargs,
            "organization_id": scope.tenant_id,
            "platform_scope": scope.platform,
            "dedupe_key": key,
            "run_after": task.run_after or timezone.now(),
            # The worker continues this trace (ADR 0008).
            "traceparent": tracing.current_traceparent(),
        }
        try:
            with transaction.atomic():
                record = TaskRecord.objects.create(**fields)
        except IntegrityError:
            # Already waiting or running: that one stands for this one.
            record = TaskRecord.objects.get(
                dedupe_key=key, status__in=[TaskStatus.READY, TaskStatus.RUNNING]
            )
        else:
            task_enqueued.send(type(self), task_result=to_result(record, self.alias, task))
        return to_result(record, self.alias, task)

    def get_result(self, result_id: str) -> TaskResult[..., Any]:
        record = TaskRecord.objects.filter(pk=result_id).first()
        if record is None:
            raise TaskResultDoesNotExist(result_id)
        return to_result(record, self.alias)


def to_result(
    record: TaskRecord, alias: str, task: Task[..., Any] | None = None
) -> TaskResult[..., Any]:
    if task is None:
        task = import_string(record.task_path)
    result: TaskResult[..., Any] = TaskResult(
        task=task,
        id=str(record.pk),
        status=TaskResultStatus(record.status),
        enqueued_at=record.enqueued_at,
        started_at=record.started_at,
        finished_at=record.finished_at,
        last_attempted_at=record.last_attempted_at,
        args=record.args,
        kwargs=record.kwargs,
        backend=alias,
        errors=[
            TaskError(exception_class_path=e["exception_class_path"], traceback=e["traceback"])
            for e in record.errors
        ],
        worker_ids=list(record.worker_ids),
    )
    object.__setattr__(result, "_return_value", record.return_value)
    return result
