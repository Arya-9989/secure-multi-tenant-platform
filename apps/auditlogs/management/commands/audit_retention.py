"""Drop audit partitions older than the retention period (PostgreSQL, ADR 0006).

Run as the schema owner (detaching and dropping a partition needs ownership):
``DATABASE_REQUIRE_RLS=False python manage.py audit_retention --keep-months 12``.

For every chain with rows in a partition about to go, a checkpoint records the
last sequence number and hash dropped, so verification can tell a retention
cut from a deletion. The run is itself an audited platform event.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import connection, transaction

from apps.auditlogs import partitions
from apps.auditlogs.models import AuditAction, AuditChainCheckpoint
from apps.auditlogs.services import record
from apps.common import rls

CHAIN_ENDS = """
    SELECT DISTINCT ON (organization_id) organization_id, chain_seq, hash, created_at
      FROM {partition}
     ORDER BY organization_id, chain_seq DESC
"""


class Command(BaseCommand):
    help = "Drop whole monthly audit partitions older than --keep-months, keeping checkpoints."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--keep-months", type=int, required=True)
        parser.add_argument("--dry-run", action="store_true", help="Report, change nothing.")

    def handle(self, *args: Any, **options: Any) -> None:
        if not partitions.is_partitioned(connection):
            raise CommandError("Retention by partition needs PostgreSQL.")
        keep: int = options["keep_months"]
        if keep < 1:
            raise CommandError("--keep-months must be at least 1.")
        cutoff = partitions.add_months(partitions.current_month(), -keep)
        expired = [p for p in partitions.partitions(connection) if p.end <= cutoff]
        if not expired:
            self.stdout.write(f"Nothing older than {cutoff:%Y-%m}.")
            return
        with rls.platform_scope():  # the platform's own housekeeping
            for partition in expired:
                self._drop(partition, dry_run=options["dry_run"])

    def _drop(self, partition: partitions.Partition, *, dry_run: bool) -> None:
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(f"SELECT count(*) FROM {partition.name}")  # noqa: S608 - our own name
            rows = cursor.fetchone()[0]
            cursor.execute(CHAIN_ENDS.format(partition=partition.name))
            ends = cursor.fetchall()
            if dry_run:
                self.stdout.write(f"Would drop {partition.name}: {rows} event(s).")
                return
            for organization_id, seq, digest, created_at in ends:
                latest = (
                    AuditChainCheckpoint.objects.filter(organization_id=organization_id)
                    .order_by("-chain_seq")
                    .values_list("chain_seq", flat=True)
                    .first()
                )
                if latest is None or seq > latest:
                    AuditChainCheckpoint.objects.create(
                        organization_id=organization_id,
                        chain_seq=seq,
                        hash=digest,
                        last_created_at=created_at,
                        partition=partition.name,
                    )
            cursor.execute(f"ALTER TABLE {partitions.PARENT} DETACH PARTITION {partition.name}")
            cursor.execute(f"DROP TABLE {partition.name}")
            record(
                AuditAction.AUDIT_RETENTION_APPLIED,
                metadata={"partition": partition.name, "events": rows, "chains": len(ends)},
            )
        self.stdout.write(f"Dropped {partition.name}: {rows} event(s), {len(ends)} chain(s).")
