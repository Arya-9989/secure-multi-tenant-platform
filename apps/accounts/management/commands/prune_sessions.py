"""Delete sessions that ended long ago (refresh-token families, ADR 0002).

A session row is needed while its tokens could still be presented (to detect
reuse) and for a while after, to answer "who was signed in when". Rows that
ended (revoked or expired) more than ``--days`` ago are deleted. Run it from
cron or a scheduler; it is idempotent.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db.models import Q
from django.utils import timezone

from apps.accounts.models import RefreshTokenFamily
from apps.common import rls


class Command(BaseCommand):
    help = "Delete sessions that were revoked or expired more than --days ago."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--days", type=int, default=30, help="Keep ended sessions this long.")

    def handle(self, *args: Any, **options: Any) -> None:
        days: int = options["days"]
        if days < 0:
            raise CommandError("--days must not be negative.")
        cutoff = timezone.now() - timedelta(days=days)
        with rls.platform_scope():  # housekeeping across every tenant
            deleted, _ = RefreshTokenFamily.objects.filter(
                Q(revoked_at__lt=cutoff) | Q(expires_at__lt=cutoff)
            ).delete()
        self.stdout.write(f"Deleted {deleted} session(s) that ended before {cutoff:%Y-%m-%d}.")
