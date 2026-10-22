"""Monthly range partitions of the audit log, and retention by partition (ADR 0006).

PostgreSQL only. Partitions are named ``auditlogs_auditlog_pYYYYMM`` and cover
``[first day of the month, first day of the next)`` in UTC. A default partition
catches anything outside them, so an insert never fails for want of one. The
runtime role gets no privilege on any partition: everything goes through the
parent, where row-level security and the append-only trigger live.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from django.db.backends.base.base import BaseDatabaseWrapper

from apps.common.rls_migrations import role_exists, runtime_role

logger = logging.getLogger(__name__)

PARENT = "auditlogs_auditlog"
DEFAULT_PARTITION = f"{PARENT}_default"
_NAME = re.compile(rf"{PARENT}_p(\d{{4}})(\d{{2}})")


class PartitionError(Exception):
    pass


def month_start(moment: date | datetime) -> date:
    return date(moment.year, moment.month, 1)


def add_months(month: date, count: int) -> date:
    index = month.year * 12 + month.month - 1 + count
    return date(index // 12, index % 12 + 1, 1)


def partition_name(month: date) -> str:
    return f"{PARENT}_p{month:%Y%m}"


def _bound(month: date) -> str:
    return f"{month:%Y-%m-%d} 00:00:00+00"


@dataclass(frozen=True, slots=True)
class Partition:
    name: str
    month: date

    @property
    def end(self) -> date:
        return add_months(self.month, 1)


def is_partitioned(connection: BaseDatabaseWrapper) -> bool:
    if connection.vendor != "postgresql":
        return False
    with connection.cursor() as cursor:
        cursor.execute("SELECT relkind = 'p' FROM pg_class WHERE oid = to_regclass(%s)", [PARENT])
        row = cursor.fetchone()
    return bool(row and row[0])


def partitions(connection: BaseDatabaseWrapper) -> list[Partition]:
    """The monthly partitions (not the default one), oldest first."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid "
            "WHERE i.inhparent = to_regclass(%s)",
            [PARENT],
        )
        names = [row[0] for row in cursor.fetchall()]
    found = []
    for name in names:
        match = _NAME.fullmatch(name)
        if match:
            found.append(Partition(name, date(int(match[1]), int(match[2]), 1)))
    return sorted(found, key=lambda p: p.month)


def _lock_out_runtime_role(cursor: Any, table: str) -> None:
    role = runtime_role()
    cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [role])
    if cursor.fetchone() is not None:
        cursor.execute(f'REVOKE ALL ON {table} FROM "{role}"')


def ensure_default_partition(connection: BaseDatabaseWrapper) -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            f"CREATE TABLE IF NOT EXISTS {DEFAULT_PARTITION} PARTITION OF {PARENT} DEFAULT"
        )
        _lock_out_runtime_role(cursor, DEFAULT_PARTITION)


def ensure_partition(connection: BaseDatabaseWrapper, month: date) -> bool:
    """Create the month's partition if missing. ``True`` if it was created."""
    name = partition_name(month)
    if any(p.name == name for p in partitions(connection)):
        return False
    start, end = _bound(month), _bound(add_months(month, 1))
    with connection.cursor() as cursor:
        cursor.execute(
            f"SELECT count(*) FROM {DEFAULT_PARTITION} "  # noqa: S608 - a fixed identifier
            "WHERE created_at >= %s AND created_at < %s",
            [start, end],
        )
        stranded = cursor.fetchone()[0]
        if stranded:
            msg = (
                f"{stranded} audit rows for {month:%Y-%m} are in the default partition; "
                "move them before creating its partition (see ADR 0006)."
            )
            raise PartitionError(msg)
        cursor.execute(
            f"CREATE TABLE {name} PARTITION OF {PARENT} FOR VALUES FROM ('{start}') TO ('{end}')"
        )
        _lock_out_runtime_role(cursor, name)
    logger.info("Created audit partition %s", name)
    return True


def ensure_months(connection: BaseDatabaseWrapper, first: date, last: date) -> list[str]:
    created, month = [], month_start(first)
    while month <= last:
        if ensure_partition(connection, month):
            created.append(partition_name(month))
        month = add_months(month, 1)
    return created


def current_month() -> date:
    return month_start(datetime.now(tz=UTC))


def runtime_role_exists(connection: BaseDatabaseWrapper) -> bool:
    return role_exists(connection, runtime_role())
