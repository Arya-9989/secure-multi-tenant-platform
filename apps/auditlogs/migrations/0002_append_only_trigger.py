"""Make the audit table append-only at the database level (PostgreSQL).

Application-level guards can be bypassed by raw SQL, a buggy migration or a
compromised code path. This trigger rejects UPDATE and DELETE on every row,
whichever role runs them; only a role allowed to drop the trigger (the table
owner) can get around it. On other databases (SQLite in local development)
it is a no-op.
"""

from django.db import migrations

FORWARD_SQL = """
CREATE OR REPLACE FUNCTION auditlogs_reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'auditlogs_auditlog is append-only (% rejected)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER auditlogs_auditlog_append_only
    BEFORE UPDATE OR DELETE ON auditlogs_auditlog
    FOR EACH ROW EXECUTE FUNCTION auditlogs_reject_mutation();
"""

REVERSE_SQL = """
DROP TRIGGER IF EXISTS auditlogs_auditlog_append_only ON auditlogs_auditlog;
DROP FUNCTION IF EXISTS auditlogs_reject_mutation();
"""


def _run(sql: str):  # type: ignore[no-untyped-def]
    def operation(apps, schema_editor):  # type: ignore[no-untyped-def]
        if schema_editor.connection.vendor == "postgresql":
            schema_editor.execute(sql, params=None)

    return operation


class Migration(migrations.Migration):
    dependencies = [("auditlogs", "0001_initial")]

    operations = [migrations.RunPython(_run(FORWARD_SQL), _run(REVERSE_SQL))]
