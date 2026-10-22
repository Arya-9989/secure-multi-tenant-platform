"""Row-level security groundwork (PostgreSQL only; see ADR 0001).

Defines the two functions every policy is written with, and grants the runtime
role (``DATABASE_RUNTIME_ROLE``) its data privileges. The settings are
transaction-local and set by ``apps.common.pgbackend``. A missing or empty
setting means "no tenant" and "no platform access": policies then match no row.
"""

from django.db import migrations

from apps.common.rls_migrations import PostgreSQLOnly, grant_runtime_role

FUNCTIONS = [
    """
    CREATE OR REPLACE FUNCTION app_current_tenant() RETURNS uuid
        LANGUAGE sql STABLE PARALLEL SAFE
        AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid $$
    """,
    """
    CREATE OR REPLACE FUNCTION app_platform_access() RETURNS boolean
        LANGUAGE sql STABLE PARALLEL SAFE
        AS $$ SELECT coalesce(current_setting('app.platform', true), '') = 'on' $$
    """,
]

DROP_FUNCTIONS = [
    "DROP FUNCTION IF EXISTS app_current_tenant()",
    "DROP FUNCTION IF EXISTS app_platform_access()",
]


class Migration(migrations.Migration):
    dependencies: list[tuple[str, str]] = []

    operations = [
        PostgreSQLOnly(FUNCTIONS, DROP_FUNCTIONS, "Row-level security scope functions"),
        migrations.RunPython(grant_runtime_role, migrations.RunPython.noop),
    ]
