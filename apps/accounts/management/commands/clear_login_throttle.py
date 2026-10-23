"""Clear an account's per-account sign-in delay (ADR 0003).

For a support case during a targeted attack: the account's owner, on a new
device, is waiting out delays caused by someone else's failed attempts.
Devices that signed in before are never affected and keep their own counters.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandParser

from apps.accounts import login_throttle


class Command(BaseCommand):
    help = "Forget the failed sign-in attempts counted against an email address."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("email")

    def handle(self, *args: Any, **options: Any) -> None:
        login_throttle.clear(options["email"])
        self.stdout.write(self.style.SUCCESS("Cleared the account's sign-in throttle."))
