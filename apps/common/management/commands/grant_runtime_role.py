"""Grant the runtime database role its privileges (row-level security, ADR 0001).

Migrations do this when the role already exists. Run this after creating the
role later, or after restoring a dump. It is idempotent. Connect as the schema
owner: ``DATABASE_REQUIRE_RLS=False python manage.py grant_runtime_role``.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from apps.common.rls_migrations import grant_runtime_privileges, role_exists, runtime_role


class Command(BaseCommand):
    help = "Grant DATABASE_RUNTIME_ROLE the data privileges the API needs (PostgreSQL)."

    def handle(self, *args: Any, **options: Any) -> None:
        if connection.vendor != "postgresql":
            raise CommandError("Row-level security and the runtime role need PostgreSQL.")
        role = runtime_role()
        if not role_exists(connection, role):
            raise CommandError(f"Database role {role!r} does not exist. Create it first.")
        grant_runtime_privileges(connection, role)
        self.stdout.write(self.style.SUCCESS(f"Granted runtime privileges to {role!r}."))
