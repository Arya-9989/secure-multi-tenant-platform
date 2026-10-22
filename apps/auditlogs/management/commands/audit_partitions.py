"""Create the audit log's upcoming monthly partitions (PostgreSQL, ADR 0006).

Run it monthly (cron, a scheduler) as the schema owner:
``DATABASE_REQUIRE_RLS=False python manage.py audit_partitions --months-ahead 3``.
Idempotent. Rows outside every partition land in the default partition, so a
missed run never loses an event; this command then refuses that month until
they are moved.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import connection

from apps.auditlogs import partitions


class Command(BaseCommand):
    help = "Create the current and upcoming monthly partitions of the audit log."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--months-ahead", type=int, default=3)

    def handle(self, *args: Any, **options: Any) -> None:
        if not partitions.is_partitioned(connection):
            raise CommandError("The audit log is partitioned on PostgreSQL only.")
        ahead: int = options["months_ahead"]
        if not 0 <= ahead <= 36:
            raise CommandError("--months-ahead must be between 0 and 36.")
        this_month = partitions.current_month()
        try:
            created = partitions.ensure_months(
                connection, this_month, partitions.add_months(this_month, ahead)
            )
        except partitions.PartitionError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(
            f"Created {len(created)} partition(s): {', '.join(created)}"
            if created
            else "Every partition already exists."
        )
