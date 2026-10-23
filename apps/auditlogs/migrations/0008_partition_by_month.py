"""Partition the audit log by month and give existing rows their hash chains (ADR 0006).

PostgreSQL: the table is rebuilt as ``PARTITION BY RANGE (created_at)`` with a
default partition and monthly partitions from its oldest row to twelve months
ahead. Rows are copied across with their chain fields computed (rows written
before chains existed are chained in time order), then the append-only
trigger, the indexes, the foreign keys, row-level security and the grants are
put back on the new parent. Reversible: the reverse rebuilds a plain table.

SQLite: no partitioning; existing rows just get their chain fields.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from django.db import migrations

from apps.auditlogs import chain, partitions
from apps.common import rls
from apps.common.rls_migrations import (
    append_only_table,
    grant_runtime_privileges,
    role_exists,
    runtime_role,
)

TABLE = partitions.PARENT
OLD = f"{TABLE}_old"
TRIGGER = f"""
    CREATE TRIGGER auditlogs_auditlog_append_only
        BEFORE UPDATE OR DELETE ON {TABLE}
        FOR EACH ROW EXECUTE FUNCTION auditlogs_reject_mutation()
"""
COLUMNS = (
    "id", "created_at", "actor_email", "action", "target_type", "target_id", "metadata",
    "ip_address", "user_agent", "request_id", "actor_id", "organization_id",
    "chain_seq", "prev_hash", "hash",
)  # fmt: skip


def _chained(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Give rows that predate hash chains their place in their tenant's chain."""
    by_chain: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for row in sorted(rows, key=lambda r: (str(r["organization_id"]), r["created_at"], str(r["id"]))):
        by_chain[row["organization_id"]].append(row)
    for chain_rows in by_chain.values():
        if all(row["chain_seq"] for row in chain_rows):
            continue  # already chained
        previous = chain.GENESIS
        for seq, row in enumerate(chain_rows, start=1):
            row["chain_seq"], row["prev_hash"] = seq, previous
            row["hash"] = previous = chain.compute_hash(row)
    return [row for chain_rows in by_chain.values() for row in chain_rows]


def _rebuild(schema_editor: Any, *, partitioned: bool) -> None:
    connection = schema_editor.connection
    with connection.cursor() as cursor:
        cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cursor.execute(
            "SELECT indexname, indexdef FROM pg_indexes WHERE tablename = %s "
            "AND indexname NOT LIKE %s",
            [TABLE, "%pkey"],
        )
        indexes = cursor.fetchall()
        cursor.execute(
            "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid = %s::regclass AND contype = 'f'",
            [TABLE],
        )
        foreign_keys = cursor.fetchall()
        cursor.execute(f"ALTER TABLE {TABLE} RENAME TO {OLD}")
        cursor.execute(f"ALTER TABLE {OLD} RENAME CONSTRAINT {TABLE}_pkey TO {OLD}_pkey")
        suffix = " PARTITION BY RANGE (created_at)" if partitioned else ""
        cursor.execute(f"CREATE TABLE {TABLE} (LIKE {OLD} INCLUDING DEFAULTS){suffix}")
        primary_key = "(id, created_at)" if partitioned else "(id)"
        cursor.execute(f"ALTER TABLE {TABLE} ADD CONSTRAINT {TABLE}_pkey PRIMARY KEY {primary_key}")

        columns = ", ".join(COLUMNS)
        cursor.execute(f"SELECT {columns} FROM {OLD}")  # noqa: S608 - fixed identifiers
        rows = [dict(zip(COLUMNS, row, strict=True)) for row in cursor.fetchall()]
    if partitioned:
        partitions.ensure_default_partition(connection)
        oldest = min((row["created_at"] for row in rows), default=None)
        first = partitions.month_start(oldest) if oldest else partitions.current_month()
        partitions.ensure_months(
            connection, first, partitions.add_months(partitions.current_month(), 12)
        )
        rows = _chained(rows)
    with connection.cursor() as cursor:
        placeholders = ", ".join(["%s"] * len(COLUMNS))
        cursor.executemany(
            f"INSERT INTO {TABLE} ({', '.join(COLUMNS)}) VALUES ({placeholders})",  # noqa: S608
            [
                [
                    *(row[name] for name in COLUMNS[:6]),
                    _json(row["metadata"]),
                    *(row[name] for name in COLUMNS[7:]),
                ]
                for row in rows
            ],
        )
        cursor.execute(f"DROP TABLE {OLD}")
        for _name, definition in indexes:
            cursor.execute(definition)
        for name, definition in foreign_keys:
            cursor.execute(f"ALTER TABLE {TABLE} ADD CONSTRAINT {name} {definition}")
        cursor.execute(TRIGGER)
        for statement in append_only_table(TABLE).forwards:
            cursor.execute(statement)
    if role_exists(connection, runtime_role()):
        grant_runtime_privileges(connection, runtime_role())


def _json(value: Any) -> str:
    import json  # noqa: PLC0415

    return json.dumps(value)


def forwards(apps: Any, schema_editor: Any) -> None:
    with rls.platform_scope():  # FORCE RLS binds the owner too
        if schema_editor.connection.vendor == "postgresql":
            _rebuild(schema_editor, partitioned=True)
            return
        model = apps.get_model("auditlogs", "AuditLog")
        fields = [f for f in chain.HASHED_FIELDS if f not in {"chain_seq", "prev_hash"}]
        rows = list(model.objects.values(*fields, "chain_seq", "prev_hash", "hash"))
        for row in _chained(rows):
            model.objects.filter(pk=row["id"]).update(
                chain_seq=row["chain_seq"], prev_hash=row["prev_hash"], hash=row["hash"]
            )


def backwards(apps: Any, schema_editor: Any) -> None:
    if schema_editor.connection.vendor == "postgresql":
        with rls.platform_scope():
            _rebuild(schema_editor, partitioned=False)


class Migration(migrations.Migration):
    dependencies = [("auditlogs", "0007_hash_chain")]

    operations = [migrations.RunPython(forwards, backwards)]
