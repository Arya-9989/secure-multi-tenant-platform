"""Run background tasks (ADR 0007). Stops after the task in hand on SIGTERM/SIGINT."""

from __future__ import annotations

import secrets
import signal
import socket
import threading
from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandParser

from apps.tasks import worker


class Command(BaseCommand):
    help = "Claim and run queued tasks until stopped."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--queue", default="default")
        parser.add_argument("--interval", type=float, default=1.0, help="Idle poll interval.")
        parser.add_argument("--batch", type=int, default=10, help="Tasks claimed at a time.")
        parser.add_argument("--once", action="store_true", help="Run what is ready, then exit.")
        parser.add_argument(
            "--heartbeat",
            type=Path,
            help="File touched after every poll that reached the database (for health checks).",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        worker_id = f"{socket.gethostname()}:{secrets.token_hex(4)}"
        stop = threading.Event()
        if not options["once"]:
            for signum in (signal.SIGTERM, signal.SIGINT):
                signal.signal(signum, lambda *_: stop.set())
        self.stdout.write(f"Worker {worker_id} on queue {options['queue']!r}.")
        while not stop.is_set():
            statuses = worker.run_once(
                worker_id=worker_id, queue=options["queue"], limit=options["batch"]
            )
            if options["heartbeat"]:
                options["heartbeat"].touch()
            if statuses:
                self.stdout.write(f"Ran {len(statuses)} task(s): {', '.join(statuses)}")
            if options["once"]:
                return
            if not statuses:
                stop.wait(options["interval"])
