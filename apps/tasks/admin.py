"""Inspection-only: what is queued, running, failed. Arguments are not shown."""

from django.contrib import admin

from apps.accounts.admin import ViewOnlyAdmin
from apps.tasks.models import TaskRecord


@admin.register(TaskRecord)
class TaskRecordAdmin(ViewOnlyAdmin[TaskRecord]):
    list_display = ("task_path", "status", "attempts", "organization", "enqueued_at", "run_after")
    list_filter = ("status", "queue_name", "task_path")
    list_select_related = ("organization",)
    # Arguments can carry sealed secrets (an invitation's encrypted token): not shown.
    fields = (
        "id",
        "task_path",
        "queue_name",
        "priority",
        "status",
        "attempts",
        "organization",
        "platform_scope",
        "enqueued_at",
        "run_after",
        "started_at",
        "finished_at",
        "worker_ids",
        "errors",
    )
