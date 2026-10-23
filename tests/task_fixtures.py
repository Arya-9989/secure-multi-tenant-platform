"""Tasks used by test_tasks.py (they must be importable by path, like real ones)."""

from __future__ import annotations

from django.tasks import task

from apps.accounts.models import User
from apps.tasks.backend import PermanentTaskError

CALLS: list[str] = []


@task
def remember(value: str) -> str:
    CALLS.append(value)
    return value.upper()


@task
def count_visible_users() -> int:
    """What the database lets this task see: its scope decides (ADR 0001)."""
    return User.objects.count()


@task
def always_fails() -> None:
    raise ConnectionError("downstream is down")


@task
def fails_for_good() -> None:
    raise PermanentTaskError("bad input, retrying will not help")


@task(priority=10)
def urgent(value: str) -> str:
    CALLS.append(f"urgent:{value}")
    return value
