"""PostgreSQL row-level security: the second, database-enforced isolation layer.

These tests go around the application on purpose: raw SQL that never calls
``visible_to()``, ORM queries without scoping, a view with the application's
tenant checks switched off, and a fresh connection that never set a scope. The
database must still refuse to show or change another tenant's rows (ADR 0001).

The rest of the suite also runs as the runtime role under these policies, so
every other test doubles as proof that the application works with RLS enforced.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest
from django.apps import apps
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError, connection, transaction
from django.db.migrations.state import ProjectState
from django.db.models import Model
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from apps.accounts.backends import TenantModelBackend
from apps.accounts.models import Invitation, User
from apps.accounts.roles import Role
from apps.accounts.scopes import scope_for_account, scope_for_invitation
from apps.auditlogs.models import AuditAction, AuditLog
from apps.auditlogs.services import record
from apps.common import rls
from apps.common.permissions import TenantObjectPermission
from apps.common.pgbackend.base import DatabaseWrapper, is_data_statement
from apps.common.rls_migrations import grant_runtime_role, runtime_role, tenant_table
from apps.common.tenancy import TenantQuerySet
from apps.organizations.models import Organization
from tests.conftest import POSTGRES, ClientFactory, World, as_schema_owner

ROOT = Path(__file__).resolve().parent.parent

pytestmark = [
    pytest.mark.django_db,
    pytest.mark.skipif(not POSTGRES, reason="row-level security is PostgreSQL-only"),
]

TENANT_COLUMNS = {
    "accounts_user": "organization_id",
    "accounts_invitation": "organization_id",
    "auditlogs_auditlog": "organization_id",
    "organizations_organization": "id",
}


def tenant_models() -> list[type[Model]]:
    """Every model whose rows belong to a tenant (its manager is tenant-aware)."""
    return [
        model
        for model in apps.get_models()
        if isinstance(model._default_manager.all(), TenantQuerySet)
    ]


def raw(sql: str, params: list[Any] | None = None) -> list[tuple[Any, ...]]:
    """Plain SQL through Django's connection: no ORM, no ``visible_to()``."""
    with connection.cursor() as cursor:
        cursor.execute(sql, params or [])
        return cursor.fetchall() if cursor.description else []


def rowcount(sql: str, params: list[Any]) -> int:
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        return int(cursor.rowcount)


@contextmanager
def refused(match: str = "row-level security") -> Iterator[None]:
    """The statement must fail; the surrounding transaction stays usable."""
    with pytest.raises(DatabaseError, match=match), transaction.atomic():
        yield


# ---------------------------------------------------------------- structure
def test_the_suite_runs_as_the_runtime_role() -> None:
    ((user, superuser, bypass),) = raw(
        "SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
    )
    assert user == runtime_role()
    assert (superuser, bypass) == (False, False)


def test_every_tenant_table_has_forced_row_level_security_and_policies() -> None:
    """Fails the build when a new tenant-owned model ships without RLS."""
    tables = {model._meta.db_table for model in tenant_models()}
    assert set(TENANT_COLUMNS) <= tables
    for table in sorted(tables):
        ((enabled, forced),) = raw(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = %s::regclass",
            [table],
        )
        assert (enabled, forced) == (True, True), table
        policies = raw("SELECT policyname FROM pg_policies WHERE tablename = %s", [table])
        assert policies, f"{table} has row-level security but no policy"


def test_the_runtime_role_owns_nothing_it_is_protected_by() -> None:
    owned = raw(
        "SELECT relname FROM pg_class WHERE relowner = (SELECT oid FROM pg_roles"
        " WHERE rolname = current_user) AND relkind IN ('r', 'p')"
    )
    assert owned == []


# ---------------------------------------------------------------- reads
@pytest.mark.parametrize(("table", "column"), sorted(TENANT_COLUMNS.items()))
def test_raw_sql_only_reads_the_scoped_tenant(world: World, table: str, column: str) -> None:
    with rls.tenant_scope(world.org_a.pk):
        tenants = {row[0] for row in raw(f"SELECT {column} FROM {table}")}  # noqa: S608
    assert tenants == {world.org_a.pk}


def test_raw_sql_cannot_fetch_a_foreign_row_by_id(world: World) -> None:
    with rls.tenant_scope(world.org_a.pk):
        assert raw("SELECT email FROM accounts_user WHERE id = %s", [world.admin_b.pk]) == []
        assert raw("SELECT 1 FROM accounts_invitation WHERE id = %s", [world.invitation_b.pk]) == []
        assert raw("SELECT 1 FROM auditlogs_auditlog WHERE id = %s", [world.audit_b.pk]) == []
        assert raw("SELECT 1 FROM organizations_organization WHERE id = %s", [world.org_b.pk]) == []
        # Joins and aggregates are filtered too: nothing to count across tenants.
        ((count,),) = raw("SELECT count(*) FROM accounts_user u JOIN accounts_invitation i ON true")
        assert count == 3 * 1


def test_orm_queries_without_visible_to_are_still_scoped(world: World) -> None:
    with rls.tenant_scope(world.org_b.pk):
        assert set(User.objects.values_list("organization_id", flat=True)) == {world.org_b.pk}
        assert list(Organization.objects.all()) == [world.org_b]
        assert list(Invitation.objects.all()) == [world.invitation_b]
        assert list(AuditLog.objects.all()) == [world.audit_b]
        assert not User.objects.filter(role=Role.SUPER_ADMIN).exists()


def test_platform_level_audit_events_are_hidden_from_every_tenant(world: World) -> None:
    record(AuditAction.LOGIN_FAILED, metadata={"email": "nobody@x.test"})  # platform scope
    with rls.tenant_scope(world.org_a.pk):
        assert raw("SELECT 1 FROM auditlogs_auditlog WHERE organization_id IS NULL") == []
    assert AuditLog.objects.filter(organization__isnull=True).count() == 1


def test_super_admins_are_invisible_to_tenants(world: World) -> None:
    with rls.tenant_scope(world.org_a.pk):
        assert raw("SELECT 1 FROM accounts_user WHERE id = %s", [world.super_admin.pk]) == []


# ---------------------------------------------------------------- writes
def test_raw_sql_cannot_modify_or_delete_foreign_rows(world: World) -> None:
    before = {
        "user": User.objects.filter(pk=world.member_b.pk).values().get(),
        "invitation": Invitation.objects.filter(pk=world.invitation_b.pk).values().get(),
    }
    with rls.tenant_scope(world.org_a.pk):
        assert (
            rowcount(
                "UPDATE accounts_user SET full_name = 'pwned', role = 'ORG_ADMIN' WHERE id = %s",
                [world.member_b.pk],
            )
            == 0
        )
        assert rowcount("UPDATE accounts_user SET token_version = token_version + 1", []) == 3, (
            "only tenant A's three users"
        )
        assert (
            rowcount("DELETE FROM accounts_invitation WHERE id = %s", [world.invitation_b.pk]) == 0
        )
        assert rowcount("DELETE FROM accounts_invitation", []) == 1, "only tenant A's own"
    assert User.objects.filter(pk=world.member_b.pk).values().get() == before["user"]
    assert (
        Invitation.objects.filter(pk=world.invitation_b.pk).values().get() == before["invitation"]
    )


def test_raw_sql_cannot_write_rows_into_another_tenant(world: World) -> None:
    with rls.tenant_scope(world.org_a.pk):
        with refused():
            raw(
                "INSERT INTO accounts_invitation (id, organization_id, email, role, token_hash,"
                " invited_by_id, created_at, expires_at) VALUES (%s, %s, 'mole@evil.test',"
                " 'MEMBER', 'x', %s, now(), now() + interval '1 day')",
                [uuid.uuid4(), world.org_b.pk, world.admin_a.pk],
            )
        # Moving one of your own rows into another tenant is refused as well.
        with refused():
            raw(
                "UPDATE accounts_user SET organization_id = %s WHERE id = %s",
                [world.org_b.pk, world.member_a.pk],
            )
        with refused():
            raw(
                "INSERT INTO auditlogs_auditlog (id, created_at, organization_id, actor_email,"
                " action, target_type, target_id, metadata, user_agent, request_id)"
                " VALUES (%s, now(), %s, '', 'auth.logout', '', '', '{}', '', '')",
                [uuid.uuid4(), world.org_b.pk],
            )
        with refused():  # a tenant cannot forge platform-level events either
            record(AuditAction.LOGOUT, organization=None)
    assert not Invitation.objects.filter(email="mole@evil.test").exists()
    assert User.objects.get(pk=world.member_a.pk).organization == world.org_a


def test_a_tenant_can_lock_but_not_change_its_own_organization(world: World) -> None:
    with rls.tenant_scope(world.org_a.pk):
        with transaction.atomic():
            locked = Organization.objects.select_for_update().filter(pk=world.org_a.pk).first()
            assert locked == world.org_a, "the service layer's lock must keep working"
        with refused():
            raw(
                "UPDATE organizations_organization SET is_active = false WHERE id = %s",
                [world.org_a.pk],
            )
        with refused():
            Organization.objects.create(name="Shadow", slug="shadow")
        assert (
            rowcount("DELETE FROM organizations_organization WHERE id = %s", [world.org_a.pk]) == 0
        )
    world.org_a.refresh_from_db()
    assert world.org_a.is_active


def test_the_audit_log_cannot_be_rewritten_by_the_runtime_role(world: World) -> None:
    for sql in (
        "UPDATE auditlogs_auditlog SET action = 'tampered'",
        "DELETE FROM auditlogs_auditlog",
        "TRUNCATE auditlogs_auditlog",
    ):
        with refused("permission denied"):
            raw(sql)
    assert AuditLog.objects.count() == 2


def test_rls_without_update_or_delete_policies_matches_no_audit_rows(world: World) -> None:
    """The middle layer: even the owner, holding every privilege, touches no row."""
    with as_schema_owner():
        assert rowcount("UPDATE auditlogs_auditlog SET action = 'tampered'", []) == 0
        assert rowcount("DELETE FROM auditlogs_auditlog", []) == 0


def test_the_runtime_role_cannot_switch_row_level_security_off() -> None:
    for sql in (
        "ALTER TABLE accounts_user DISABLE ROW LEVEL SECURITY",
        "ALTER TABLE accounts_user NO FORCE ROW LEVEL SECURITY",
        "DROP POLICY tenant_isolation ON accounts_user",
    ):
        with refused("must be owner"):
            raw(sql)


def test_force_binds_the_schema_owner_too(world: World) -> None:
    with as_schema_owner():
        ((superuser,),) = raw("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        if superuser:
            pytest.skip("superusers bypass row-level security; CI connects as a plain owner")
        with rls.scope(rls.NO_SCOPE):
            assert raw("SELECT count(*) FROM accounts_user") == [(0,)]
        with rls.tenant_scope(world.org_a.pk):
            assert raw("SELECT count(*) FROM accounts_user") == [(3,)]


# ---------------------------------------------------------------- fail closed
@pytest.mark.parametrize("table", sorted(TENANT_COLUMNS))
def test_no_scope_sees_nothing(world: World, table: str) -> None:
    with rls.scope(rls.NO_SCOPE):
        assert raw(f"SELECT count(*) FROM {table}") == [(0,)]  # noqa: S608


def test_no_scope_writes_nothing(world: World) -> None:
    with rls.scope(rls.NO_SCOPE):
        assert rowcount("UPDATE accounts_user SET full_name = 'x'", []) == 0
        with refused():
            Organization.objects.create(name="Nowhere", slug="nowhere")
        with refused():
            Invitation.objects.create(
                organization=world.org_a,
                email="x@a.test",
                role=Role.MEMBER,
                token_hash="y",
                invited_by=world.admin_a,
                expires_at=timezone.now() + timedelta(days=1),
            )


def test_an_empty_setting_set_directly_on_the_connection_sees_nothing(world: World) -> None:
    """Bypass Django entirely: psycopg's own cursor, the settings blanked by hand."""
    with connection.cursor():  # make sure the connection is open
        pass
    with connection.connection.cursor() as cursor:
        cursor.execute(
            "SELECT set_config('app.tenant_id', '', true), set_config('app.platform', '', true)"
        )
        cursor.execute("SELECT count(*) FROM accounts_user")
        assert cursor.fetchone() == (0,)
    connection.rls_applied_scope = None  # type: ignore[attr-defined]  # we changed it by hand


def test_a_malformed_tenant_setting_is_an_error_not_a_match(world: World) -> None:
    with connection.cursor():
        pass
    savepoint = transaction.savepoint()
    try:
        with connection.connection.cursor() as cursor:
            cursor.execute("SELECT set_config('app.tenant_id', 'not-a-uuid', true)")
            with pytest.raises(psycopg.errors.InvalidTextRepresentation):
                cursor.execute("SELECT count(*) FROM accounts_user")
    finally:
        transaction.savepoint_rollback(savepoint)


@pytest.mark.django_db(transaction=True)
def test_a_fresh_connection_that_never_set_a_scope_sees_nothing() -> None:
    with rls.platform_scope():
        organization = Organization.objects.create(name="Committed", slug="committed")
        User.objects.create_user("c@c.test", "x", role=Role.ORG_ADMIN, organization=organization)
    params = connection.get_connection_params()
    params.pop("cursor_factory", None)
    params.pop("context", None)
    with psycopg.connect(**params) as conn, conn.cursor() as cursor:
        cursor.execute(f"SET ROLE {runtime_role()}")
        cursor.execute("SELECT current_setting('app.tenant_id', true)")
        assert cursor.fetchone() in {(None,), ("",)}
        cursor.execute("SELECT count(*) FROM accounts_user")
        assert cursor.fetchone() == (0,)
        cursor.execute("SELECT count(*) FROM organizations_organization")
        assert cursor.fetchone() == (0,)
        cursor.execute("SELECT set_config('app.tenant_id', %s, false)", [str(organization.pk)])
        cursor.execute("SELECT count(*) FROM accounts_user")
        assert cursor.fetchone() == (1,), "positive control"


# ---------------------------------------------------------------- the application layer off
def test_with_application_scoping_switched_off_the_database_still_isolates(
    world: World, client_for: ClientFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulate a bug that removes every application-level tenant check."""
    monkeypatch.setattr(TenantQuerySet, "visible_to", lambda self, candidate: self.all())
    monkeypatch.setattr(TenantObjectPermission, "has_object_permission", lambda *a: True)
    client = client_for(world.admin_a)

    listed = client.get(reverse("user-list"), {"page_size": 100}).json()["results"]
    assert {row["organization"] for row in listed} == {str(world.org_a.pk)}
    assert client.get(reverse("user-detail", args=[world.admin_b.pk])).status_code == 404
    response = client.post(reverse("user-deactivate", args=[world.member_b.pk]))
    assert response.status_code == 404
    assert User.objects.get(pk=world.member_b.pk).is_active
    audit = client.get(reverse("auditlog-list")).json()["results"]
    assert {row["organization"] for row in audit} == {str(world.org_a.pk)}


# ---------------------------------------------------------------- the scope bookkeeping
def _setting_on_the_connection() -> str | None:
    with connection.connection.cursor() as cursor:
        cursor.execute("SELECT current_setting('app.tenant_id', true)")
        row = cursor.fetchone()
    return None if row is None else row[0]


def _read_as_then_fail(tenant_id: uuid.UUID) -> None:
    with transaction.atomic(), rls.tenant_scope(tenant_id):
        raw("SELECT 1 FROM accounts_user")
        assert _setting_on_the_connection() == str(tenant_id)
        raise ZeroDivisionError  # roll the savepoint back


def test_the_scope_survives_savepoint_rollbacks(world: World) -> None:
    with rls.tenant_scope(world.org_a.pk):
        raw("SELECT 1 FROM accounts_user")
        assert _setting_on_the_connection() == str(world.org_a.pk)
        with pytest.raises(ZeroDivisionError):
            _read_as_then_fail(world.org_b.pk)
        # PostgreSQL restored tenant A's value; the backend's record agrees.
        assert _setting_on_the_connection() == str(world.org_a.pk)
        assert connection.rls_applied_scope == rls.for_tenant(world.org_a.pk)  # type: ignore[attr-defined]
        assert {row[0] for row in raw("SELECT organization_id FROM accounts_user")} == {
            world.org_a.pk
        }
        with transaction.atomic(), rls.tenant_scope(world.org_b.pk):  # released, not rolled back
            raw("SELECT 1")
        assert {row[0] for row in raw("SELECT organization_id FROM accounts_user")} == {
            world.org_a.pk
        }


@pytest.mark.django_db(transaction=True)
def test_statements_outside_a_transaction_get_one_of_their_own() -> None:
    with rls.platform_scope():
        organization = Organization.objects.create(name="Solo", slug="solo")
        User.objects.create_user("s@s.test", "x", role=Role.ORG_ADMIN, organization=organization)
    assert connection.get_autocommit()
    with rls.tenant_scope(organization.pk):
        assert User.objects.count() == 1
    assert connection.rls_applied_scope is None  # type: ignore[attr-defined]
    assert _setting_on_the_connection() in {None, ""}, "nothing lingers on the session"
    with rls.scope(rls.NO_SCOPE):
        assert User.objects.count() == 0


@pytest.mark.parametrize(
    ("sql", "data"),
    [
        ("SELECT 1", True),
        ("  with x as (select 1) select * from x", True),
        ("INSERT INTO t VALUES (1)", True),
        ("CREATE DATABASE test_x", False),
        ("create index concurrently i on t (c)", False),
        ("SAVEPOINT s1", False),
        ("RELEASE SAVEPOINT s1", False),
        ("SET CONSTRAINTS ALL IMMEDIATE", False),
        ("TRUNCATE t", False),
        ("VACUUM", False),
    ],
)
def test_only_data_statements_get_the_scope(sql: str, data: bool) -> None:
    assert is_data_statement(sql) is data


def test_statements_that_are_not_strings_get_the_scope() -> None:
    assert is_data_statement(object())


# ---------------------------------------------------------------- roles at connect time
def _wrapper(**options: Any) -> DatabaseWrapper:
    settings_dict = {**connection.settings_dict, "OPTIONS": {**options}}
    return DatabaseWrapper(settings_dict, alias="rls-check")


@override_settings(DATABASE_REQUIRE_RLS=True)
def test_connections_refuse_a_role_that_would_bypass_row_level_security() -> None:
    owner = _wrapper()
    try:
        with pytest.raises(ImproperlyConfigured, match="row-level security would not apply"):
            owner.ensure_connection()
    finally:
        owner.close()
    runtime = _wrapper(assume_role=runtime_role())
    try:
        runtime.ensure_connection()
        assert runtime.connection is not None
    finally:
        runtime.close()


# ---------------------------------------------------------------- resolvers and operators
def test_pre_authentication_resolvers_return_only_a_scope(world: World) -> None:
    assert scope_for_account(email="Admin@A.test") == rls.for_tenant(world.org_a.pk)
    assert scope_for_account(user_id=world.member_b.pk) == rls.for_tenant(world.org_b.pk)
    assert scope_for_account(email="root@platform.test") == rls.PLATFORM
    assert scope_for_account(email="nobody@x.test") == rls.NO_SCOPE
    assert scope_for_account(user_id="not-a-uuid") == rls.NO_SCOPE
    assert scope_for_invitation("no-such-hash") == rls.NO_SCOPE
    assert scope_for_invitation(world.invitation_b.token_hash) == rls.for_tenant(world.org_b.pk)


def test_a_scope_is_one_tenant_or_the_platform() -> None:
    with pytest.raises(ValueError, match="not both"):
        rls.DbScope(tenant_id=uuid.uuid4(), platform=True)
    assert str(rls.NO_SCOPE) == "none"
    assert str(rls.PLATFORM) == "platform"
    tenant = uuid.uuid4()
    assert str(rls.for_tenant(str(tenant))) == f"tenant:{tenant}"


def test_grant_runtime_role_is_idempotent_and_keeps_the_audit_log_append_only() -> None:
    with as_schema_owner():
        call_command("grant_runtime_role", stdout=open(os.devnull, "w"))  # noqa: SIM115
        call_command("grant_runtime_role", stdout=open(os.devnull, "w"))  # noqa: SIM115
        privileges = raw(
            "SELECT privilege_type FROM information_schema.role_table_grants"
            " WHERE grantee = %s AND table_name = 'auditlogs_auditlog'",
            [runtime_role()],
        )
    assert {row[0] for row in privileges} == {"SELECT", "INSERT"}


@override_settings(DATABASE_RUNTIME_ROLE="no_such_role")
def test_grant_runtime_role_needs_an_existing_role() -> None:
    with pytest.raises(CommandError, match="does not exist"):
        call_command("grant_runtime_role")


@override_settings(DATABASE_RUNTIME_ROLE="Robert'); DROP TABLE x;--")
def test_the_runtime_role_name_must_be_a_plain_identifier() -> None:
    with pytest.raises(ValueError, match="plain lowercase identifier"):
        runtime_role()


def _manage(*args: str, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - our own interpreter and manage.py
        [sys.executable, "manage.py", *args],
        cwd=ROOT,
        env={**os.environ, "DJANGO_DEBUG": "True", "DATABASE_URL": "sqlite://:memory:", **env},
        capture_output=True,
        text=True,
        check=False,
    )


def test_operators_opt_in_to_platform_scope_explicitly() -> None:
    show = "from apps.common import rls; print(rls.current_scope())"
    assert _manage("shell", "-c", show).stdout.split()[-1] == "none"
    assert _manage("shell", "-c", show, APP_DB_SCOPE="platform").stdout.split()[-1] == "platform"
    bogus = _manage("shell", "-c", show, APP_DB_SCOPE="tenant")
    assert bogus.returncode != 0
    assert "APP_DB_SCOPE must be 'platform'" in bogus.stderr


# ---------------------------------------------------------------- migration operations
class _Editor:
    def __init__(self, conn: Any) -> None:
        self.connection = conn
        self.executed: list[str] = []

    def execute(self, sql: str, params: Any = None) -> None:
        self.executed.append(sql)


def _row_security(table: str) -> tuple[bool, bool, int]:
    ((enabled, forced),) = raw(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = %s::regclass",
        [table],
    )
    ((policies,),) = raw("SELECT count(*) FROM pg_policies WHERE tablename = %s", [table])
    return enabled, forced, policies


def test_rls_migrations_are_reversible() -> None:
    operation = tenant_table("accounts_invitation")
    assert operation.describe() == "Row-level security on accounts_invitation"
    assert operation.deconstruct()[0] == "PostgreSQLOnly"
    with as_schema_owner():
        raw("SET CONSTRAINTS ALL IMMEDIATE")
        with connection.schema_editor() as editor:
            operation.database_backwards("accounts", editor, ProjectState(), ProjectState())
        assert _row_security("accounts_invitation") == (False, False, 0)
        with connection.schema_editor() as editor:
            operation.database_forwards("accounts", editor, ProjectState(), ProjectState())
        assert _row_security("accounts_invitation") == (True, True, 1)


def test_rls_migrations_do_nothing_on_other_databases() -> None:
    editor = _Editor(type("SQLite", (), {"vendor": "sqlite"})())
    operation = tenant_table("accounts_user")
    operation.database_forwards("accounts", editor, ProjectState(), ProjectState())  # type: ignore[arg-type]
    operation.database_backwards("accounts", editor, ProjectState(), ProjectState())  # type: ignore[arg-type]
    grant_runtime_role(None, editor)  # type: ignore[arg-type]
    assert editor.executed == []


@override_settings(DATABASE_RUNTIME_ROLE="no_such_role")
def test_migrations_skip_the_grants_when_the_role_does_not_exist(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level("WARNING", logger="apps.common.rls_migrations"):
        grant_runtime_role(None, _Editor(connection))  # type: ignore[arg-type]
    assert "does not exist" in caplog.text


def test_the_session_backend_resolves_unknown_users_to_nobody(world: World) -> None:
    backend = TenantModelBackend()
    assert backend.get_user(uuid.uuid4()) is None
    assert backend.get_user(world.member_a.pk) == world.member_a
    assert backend.authenticate(None, username="nobody@x.test", password="x") is None
