"""Verify the audit log's hash chains (ADR 0006). Exits 1 if anything is wrong.

Reports modified rows (hash mismatch), deleted rows (sequence gaps), rows that do
not follow their predecessor (re-linked or reordered), duplicated sequence
numbers, and chains that end before what the SIEM already received.
"""

from __future__ import annotations

import uuid
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from apps.auditlogs import chain
from apps.auditlogs.models import AuditChainCheckpoint, AuditExportCursor, AuditLog
from apps.common import rls
from apps.organizations.models import Organization


class Command(BaseCommand):
    help = "Verify every audit hash chain (or one organization's) and report tampering."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--organization", help="Only this organization's chain (UUID).")
        parser.add_argument(
            "--platform", action="store_true", help="Only the platform-level chain."
        )

    def handle(self, *args: Any, **options: Any) -> None:
        with rls.platform_scope():  # a system check over every tenant's chain
            names = dict(Organization.objects.values_list("pk", "name"))
            if options["organization"]:
                chains: list[str | None] = [options["organization"]]
            elif options["platform"]:
                chains = [None]
            else:
                ordered = sorted(names, key=lambda pk: names[pk])
                chains = [None, *(str(pk) for pk in ordered)]
            findings = 0
            for organization_id in chains:
                report = self._verify(organization_id)
                findings += len(report.findings)
                status = "OK" if not report.findings else f"{len(report.findings)} problem(s)"
                label = report.chain
                if organization_id is not None:
                    label = f"{names.get(uuid.UUID(organization_id), '?')} ({organization_id})"
                self.stdout.write(
                    f"{label}: {report.rows} event(s), head {report.head_seq}: {status}"
                )
                for finding in report.findings:
                    self.stdout.write(f"  {finding}")
        if findings:
            msg = f"The audit log failed verification: {findings} problem(s)."
            raise CommandError(msg)
        self.stdout.write(self.style.SUCCESS("Every audit chain verified."))

    def _verify(self, organization_id: str | None) -> chain.ChainReport:
        key = chain.chain_key(organization_id)
        tenant: dict[str, Any] = (
            {"organization_id": organization_id} if organization_id else {"organization": None}
        )
        checkpoint = AuditChainCheckpoint.objects.filter(**tenant).order_by("-chain_seq").first()
        cursor = AuditExportCursor.objects.filter(chain=key).first()
        rows = (
            AuditLog.objects.filter(**tenant)
            .order_by("chain_seq", "created_at")
            .values(*chain.HASHED_FIELDS, "hash")
            .iterator(chunk_size=2000)
        )
        return chain.verify_chain(
            key,
            rows,
            start_seq=checkpoint.chain_seq if checkpoint else 0,
            start_hash=checkpoint.hash if checkpoint else chain.GENESIS,
            exported_seq=cursor.last_seq if cursor else 0,
        )
