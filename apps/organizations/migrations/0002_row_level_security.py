"""Row-level security on tenants: a tenant sees only its own row (ADR 0001)."""

from django.db import migrations

from apps.common.rls_migrations import grant_runtime_role, organization_table


class Migration(migrations.Migration):
    dependencies = [
        ("common", "0001_row_level_security"),
        ("organizations", "0001_initial"),
    ]

    operations = [
        organization_table("organizations_organization"),
        migrations.RunPython(grant_runtime_role, migrations.RunPython.noop),
    ]
