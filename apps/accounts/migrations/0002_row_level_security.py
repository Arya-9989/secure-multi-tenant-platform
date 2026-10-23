"""Row-level security on users and invitations (ADR 0001).

Super admins have no organization, so their rows are visible only in platform
scope.
"""

from django.db import migrations

from apps.common.rls_migrations import grant_runtime_role, tenant_table


class Migration(migrations.Migration):
    dependencies = [
        ("common", "0001_row_level_security"),
        ("accounts", "0001_initial"),
    ]

    operations = [
        tenant_table("accounts_user"),
        tenant_table("accounts_invitation"),
        migrations.RunPython(grant_runtime_role, migrations.RunPython.noop),
    ]
