"""Delete finished tasks older than ``--days`` (ADR 0007). Idempotent."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.utils import timezone

from apps.common import rls
from apps.tasks.models import TaskRecord, TaskStatus


class Command(BaseCommand):
    help = "Delete succeeded and failed tasks that finished more than --days ago."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--days", type=int, default=7)

    def handle(self, *args: Any, **options: Any) -> None:
        if options["days"] < 0:
            raise CommandError("--days must not be negative.")
        cutoff = timezone.now() - timedelta(days=options["days"])
        with rls.platform_scope():
            deleted, _ = TaskRecord.objects.filter(
                status__in=[TaskStatus.SUCCESSFUL, TaskStatus.FAILED], finished_at__lt=cutoff
            ).delete()
        self.stdout.write(f"Deleted {deleted} finished task(s).")
