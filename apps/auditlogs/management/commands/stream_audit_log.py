"""Stream the audit log to the SIEM at ``AUDIT_SIEM_URL`` (ADR 0006).

``--once`` ships what is pending and exits (for cron or a test); without it the
command polls every ``--interval`` seconds until SIGTERM or SIGINT, finishing
the batch in flight first.
"""

from __future__ import annotations

import signal
import threading
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from apps.auditlogs import siem


class Command(BaseCommand):
    help = "Ship audit events to the SIEM, in order, at least once."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--once", action="store_true", help="Ship what is pending, then exit.")
        parser.add_argument("--interval", type=float, default=5.0, help="Seconds between polls.")

    def handle(self, *args: Any, **options: Any) -> None:
        stop = threading.Event()
        if not options["once"]:
            for signum in (signal.SIGTERM, signal.SIGINT):
                signal.signal(signum, lambda *_: stop.set())
        while True:
            try:
                # A shutdown signal cuts a retry pause short (in --once mode, plain sleep).
                result = siem.ship_once(sleep=None if options["once"] else stop.wait)
            except siem.SiemDeliveryError as exc:
                if options["once"]:
                    raise CommandError(str(exc)) from exc
                self.stderr.write(f"{exc}; retrying in {options['interval']}s")
            else:
                if result.events or options["once"]:
                    self.stdout.write(
                        f"Shipped {result.events} event(s) in {result.batches} batch(es)."
                    )
            if options["once"] or stop.wait(options["interval"]):
                return
