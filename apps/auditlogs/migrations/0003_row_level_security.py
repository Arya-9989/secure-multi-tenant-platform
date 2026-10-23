"""Row-level security on the audit log: read and append within a tenant (ADR 0001).

There is no UPDATE or DELETE policy, so with RLS on those match no row; the
runtime role also lacks the privileges, and the trigger from 0002 rejects them
for every role.
"""

from django.db import migrations

from apps.common.rls_migrations import append_only_table, grant_runtime_role


class Migration(migrations.Migration):
    dependencies = [
        ("common", "0001_row_level_security"),
        ("auditlogs", "0002_append_only_trigger"),
    ]

    operations = [
        append_only_table("auditlogs_auditlog"),
        migrations.RunPython(grant_runtime_role, migrations.RunPython.noop),
    ]
