"""Background tasks stored in the database (ADR 0007)."""

from __future__ import annotations

import uuid

from django.db import models
from django.db.models import Q
from django.utils import timezone

from apps.common.tenancy import TenantQuerySet


class TaskStatus(models.TextChoices):
    # The same names as django.tasks.TaskResultStatus.
    READY = "READY", "Ready"
    RUNNING = "RUNNING", "Running"
    FAILED = "FAILED", "Failed"
    SUCCESSFUL = "SUCCESSFUL", "Successful"


class TaskRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    task_path = models.CharField(max_length=255, help_text="module.function of the task.")
    queue_name = models.CharField(max_length=100, default="default")
    priority = models.SmallIntegerField(default=0)
    args = models.JSONField(default=list)
    kwargs = models.JSONField(default=dict)
    # The database scope it was queued under (ADR 0001): a tenant, or the platform.
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="+",
    )
    platform_scope = models.BooleanField(default=False)
    dedupe_key = models.CharField(max_length=64, help_text="SHA-256 of the task and arguments.")
    status = models.CharField(max_length=16, choices=TaskStatus.choices, default=TaskStatus.READY)
    attempts = models.PositiveIntegerField(default=0)
    run_after = models.DateTimeField(default=timezone.now)
    leased_until = models.DateTimeField(null=True, blank=True)
    worker_ids = models.JSONField(default=list)
    errors = models.JSONField(default=list)
    return_value = models.JSONField(null=True, blank=True)
    traceparent = models.CharField(max_length=55, blank=True, help_text="W3C trace context.")
    enqueued_at = models.DateTimeField(default=timezone.now)
    started_at = models.DateTimeField(null=True, blank=True)
    last_attempted_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    objects = TenantQuerySet.as_manager()

    class Meta:
        verbose_name = "task"
        ordering = ("-enqueued_at",)
        indexes = (
            models.Index(fields=("queue_name", "status", "-priority", "run_after")),
            models.Index(fields=("status", "leased_until")),
        )
        constraints = (
            # The same task with the same arguments is queued once at a time.
            models.UniqueConstraint(
                fields=("dedupe_key",),
                condition=Q(status__in=["READY", "RUNNING"]),
                name="task_once_while_pending",
            ),
            models.CheckConstraint(
                condition=Q(platform_scope=False) | Q(organization__isnull=True),
                name="task_scope_is_one_tenant_or_the_platform",
            ),
        )

    def __str__(self) -> str:
        return f"{self.task_path} [{self.status}]"

    @property
    def tenant_id(self) -> uuid.UUID | None:
        return self.organization_id
