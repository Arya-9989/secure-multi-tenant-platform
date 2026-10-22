"""Migration building blocks for row-level security (PostgreSQL only).

Every tenant-owned table gets ``ENABLE`` *and* ``FORCE ROW LEVEL SECURITY``
(so the owner is bound by the policies too) and policies written in terms of
``app_current_tenant()`` and ``app_platform_access()``, defined by
``apps/common/migrations/0001_row_level_security.py``. See ADR 0001.

On other databases (SQLite in local development) these operations do nothing.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from typing import Any

from django.conf import settings
from django.db import migrations
from django.db.backends.base.base import BaseDatabaseWrapper
from django.db.backends.base.schema import BaseDatabaseSchemaEditor
from django.db.migrations.state import ProjectState

logger = logging.getLogger(__name__)

PLATFORM = "app_platform_access()"
TENANT = "app_current_tenant()"

# Tables the runtime role may append to but never rewrite.
APPEND_ONLY_TABLES: tuple[str, ...] = ("auditlogs_auditlog",)
_ROLE_NAME = re.compile(r"[a-z_][a-z0-9_]{0,62}")


class PostgreSQLOnly(migrations.operations.base.Operation):
    """Run SQL on PostgreSQL, do nothing elsewhere. Reversible."""

    reduces_to_sql = True
    reversible = True

    def __init__(self, forwards: Sequence[str], backwards: Sequence[str], label: str) -> None:
        self.forwards = tuple(forwards)
        self.backwards = tuple(backwards)
        self.label = label

    def deconstruct(self) -> tuple[str, list[Any], dict[str, Any]]:
        return (type(self).__qualname__, [self.forwards, self.backwards, self.label], {})

    def state_forwards(self, app_label: str, state: ProjectState) -> None:
        pass

    def database_forwards(
        self,
        app_label: str,
        schema_editor: BaseDatabaseSchemaEditor,
        from_state: ProjectState,
        to_state: ProjectState,
    ) -> None:
        _run(schema_editor, self.forwards)

    def database_backwards(
        self,
        app_label: str,
        schema_editor: BaseDatabaseSchemaEditor,
        from_state: ProjectState,
        to_state: ProjectState,
    ) -> None:
        _run(schema_editor, self.backwards)

    def describe(self) -> str:
        return self.label


def _run(schema_editor: BaseDatabaseSchemaEditor, statements: Sequence[str]) -> None:
    if schema_editor.connection.vendor != "postgresql":
        return
    for statement in statements:
        schema_editor.execute(statement, params=None)


def _protect(table: str, policies: Sequence[tuple[str, str]]) -> PostgreSQLOnly:
    forwards = [
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
        *(f"CREATE POLICY {name} ON {table} {body}" for name, body in policies),
    ]
    backwards = [
        *(f"DROP POLICY IF EXISTS {name} ON {table}" for name, _ in policies),
        f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY",
    ]
    return PostgreSQLOnly(forwards, backwards, f"Row-level security on {table}")


def tenant_table(table: str, column: str = "organization_id") -> PostgreSQLOnly:
    """Rows readable and writable only within their organization (or by the platform)."""
    rule = f"({PLATFORM} OR {column} = {TENANT})"
    return _protect(table, [("tenant_isolation", f"FOR ALL USING {rule} WITH CHECK {rule}")])


def organization_table(table: str) -> PostgreSQLOnly:
    """A tenant reads (and may lock) its own row; only the platform changes tenants."""
    own = f"({PLATFORM} OR id = {TENANT})"
    return _protect(
        table,
        [
            ("tenant_read", f"FOR SELECT USING {own}"),
            # SELECT ... FOR UPDATE needs an UPDATE policy; the CHECK refuses the change.
            ("tenant_lock", f"FOR UPDATE USING {own} WITH CHECK ({PLATFORM})"),
            ("platform_insert", f"FOR INSERT WITH CHECK ({PLATFORM})"),
            ("platform_delete", f"FOR DELETE USING ({PLATFORM})"),
        ],
    )


def append_only_table(table: str, column: str = "organization_id") -> PostgreSQLOnly:
    """Readable and appendable within a tenant; no UPDATE or DELETE policy exists."""
    rule = f"({PLATFORM} OR {column} = {TENANT})"
    return _protect(
        table,
        [
            ("tenant_read", f"FOR SELECT USING {rule}"),
            ("tenant_append", f"FOR INSERT WITH CHECK {rule}"),
        ],
    )


# ---------------------------------------------------------------- the runtime role
def runtime_role() -> str:
    role: str = settings.DATABASE_RUNTIME_ROLE
    if not _ROLE_NAME.fullmatch(role):
        msg = f"DATABASE_RUNTIME_ROLE must be a plain lowercase identifier, got {role!r}."
        raise ValueError(msg)
    return role


def role_exists(connection: BaseDatabaseWrapper, role: str) -> bool:
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [role])
        return cursor.fetchone() is not None


def grant_runtime_privileges(connection: BaseDatabaseWrapper, role: str) -> None:
    """Give ``role`` what the API needs and nothing more. Idempotent.

    Data privileges on every table in the schema, now and (through default
    privileges) for tables the current role creates later; then append-only
    tables and the migration history are narrowed back down.
    """
    quoted = connection.ops.quote_name(role)
    statements = [
        f"GRANT USAGE ON SCHEMA public TO {quoted}",
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {quoted}",
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {quoted}",
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {quoted}",
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {quoted}",
        f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON django_migrations FROM {quoted}",
    ]
    with connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)
        for table in APPEND_ONLY_TABLES:
            cursor.execute("SELECT to_regclass(%s)", [table])
            if cursor.fetchone()[0] is not None:
                cursor.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON {table} FROM {quoted}")
            # Partitions (ADR 0006) are reached only through the parent, where the
            # policies and the append-only trigger are: no direct privilege at all.
            cursor.execute(
                "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid "
                "WHERE i.inhparent = to_regclass(%s)",
                [table],
            )
            for (partition,) in cursor.fetchall():
                cursor.execute(f"REVOKE ALL ON {partition} FROM {quoted}")


def grant_runtime_role(apps: Any, schema_editor: BaseDatabaseSchemaEditor) -> None:
    """Migration step: grant the runtime role its privileges if it exists."""
    connection = schema_editor.connection
    if connection.vendor != "postgresql":
        return
    role = runtime_role()
    if not role_exists(connection, role):
        logger.warning(
            "Database role %r does not exist; skipped its grants. Create it and run "
            "`manage.py grant_runtime_role` (see ADR 0001).",
            role,
        )
        return
    grant_runtime_privileges(connection, role)
