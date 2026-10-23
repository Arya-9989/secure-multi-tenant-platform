"""PostgreSQL backend that runs every data statement under the current RLS scope.

Row-level security policies read ``app.tenant_id`` and ``app.platform``
(see :mod:`apps.common.rls` and ADR 0001). They are set with
``set_config(..., is_local => true)``, so they last exactly one transaction and
cannot leak into the next request on a pooled connection. This wrapper makes
sure they are always right:

* Inside a transaction, the scope is applied before the first data statement
  and again whenever the scope changes. A rolled-back savepoint reverts the
  settings in PostgreSQL, so the wrapper reverts its own record of them too.
* A data statement issued in autocommit mode runs in a transaction of its own:
  ``BEGIN``, the scope, the statement, ``COMMIT``.

Statements that do not read or write rows (DDL, ``SAVEPOINT``, ``SET``...) run
untouched, which also keeps ``CREATE DATABASE`` and ``CREATE INDEX
CONCURRENTLY`` working outside transactions.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.db.backends.base.base import NO_DB_ALIAS
from django.db.backends.postgresql import base

from apps.common.rls import PLATFORM_SETTING, TENANT_SETTING, DbScope, current_scope

APPLY_SCOPE_SQL = (
    f"SELECT set_config('{TENANT_SETTING}', %s, true), set_config('{PLATFORM_SETTING}', %s, true)"
)

# Statements that never touch table rows. Anything else (SELECT, INSERT,
# UPDATE, DELETE, WITH, MERGE, COPY, VALUES, TABLE, EXPLAIN...) gets the scope.
_NON_DATA_STATEMENT = re.compile(
    r"\s*(?:ALTER|ANALY[SZ]E|BEGIN|CHECKPOINT|CLUSTER|COMMENT|COMMIT|CREATE|DEALLOCATE|DISCARD"
    r"|DO|DROP|END|GRANT|LISTEN|LOAD|LOCK|NOTIFY|PREPARE|REASSIGN|REFRESH|REINDEX|RELEASE|RESET"
    r"|REVOKE|ROLLBACK|SAVEPOINT|SECURITY|SET|SHOW|START|TRUNCATE|UNLISTEN|VACUUM)\b",
    re.IGNORECASE,
)

# The connecting role must be subject to RLS: superusers and BYPASSRLS roles
# ignore every policy, and an owner could switch FORCE off for its tables.
ROLE_BYPASSES_RLS_SQL = """
    SELECT r.rolname, r.rolsuper, r.rolbypassrls,
           EXISTS (SELECT 1 FROM pg_class c WHERE c.relowner = r.oid AND c.relrowsecurity)
      FROM pg_roles r
     WHERE r.rolname = current_user
"""

Executor = Callable[[str, Any, bool, dict[str, Any]], Any]


def is_data_statement(sql: object) -> bool:
    return not (isinstance(sql, str) and _NON_DATA_STATEMENT.match(sql))


class DatabaseWrapper(base.DatabaseWrapper):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # The scope applied in the open transaction (None: nothing applied yet).
        self.rls_applied_scope: DbScope | None = None
        self._rls_at_savepoint: dict[str, DbScope | None] = {}
        self.execute_wrappers.append(self._apply_rls_scope)

    # ------------------------------------------------------------ connection
    def init_connection_state(self) -> None:
        super().init_connection_state()
        self._rls_forget()
        if settings.DATABASE_REQUIRE_RLS:
            self.verify_role_is_subject_to_rls()

    def verify_role_is_subject_to_rls(self) -> None:
        with self.connection.cursor() as cursor:
            cursor.execute(ROLE_BYPASSES_RLS_SQL)
            row = cursor.fetchone()
        if not self.get_autocommit():  # pragma: no cover - only with AUTOCOMMIT=False
            self.connection.commit()
        if row is None:  # pragma: no cover - current_user always exists in pg_roles
            return
        role, superuser, bypassrls, owner = row
        if superuser or bypassrls or owner:
            reason = (
                "is a superuser"
                if superuser
                else "has BYPASSRLS"
                if bypassrls
                else ("owns tables protected by row-level security")
            )
            msg = (
                f"The database role {role!r} {reason}, so row-level security would not apply. "
                "Connect as the runtime role (see ADR 0001), or set DATABASE_REQUIRE_RLS=False "
                "for migrations and operator commands that connect as the owner."
            )
            raise ImproperlyConfigured(msg)

    # ------------------------------------------------------------ the wrapper
    def _apply_rls_scope(
        self, execute: Executor, sql: str, params: Any, many: bool, context: dict[str, Any]
    ) -> Any:
        # The maintenance connection (test database creation) holds no tenant rows.
        if self.alias == NO_DB_ALIAS or not is_data_statement(sql):
            return execute(sql, params, many, context)
        scope = current_scope()
        if self.get_autocommit():
            # set_config(..., true) only lasts a transaction: give the statement one.
            with transaction.atomic(using=self.alias):
                self._set_scope(scope)
                return execute(sql, params, many, context)
        if self.rls_applied_scope != scope and not self.needs_rollback:
            self._set_scope(scope)
        return execute(sql, params, many, context)

    def _set_scope(self, scope: DbScope) -> None:
        with self.wrap_database_errors, self.connection.cursor() as cursor:
            cursor.execute(APPLY_SCOPE_SQL, scope.setting_values)
        self.rls_applied_scope = scope

    def _rls_forget(self) -> None:
        self.rls_applied_scope = None
        self._rls_at_savepoint.clear()

    # ------------------------------------------------------------ transaction bookkeeping
    # A transaction-local setting disappears at COMMIT or ROLLBACK, and a rollback to
    # a savepoint restores the value it had when the savepoint was taken.
    def _savepoint(self, sid: str) -> None:
        super()._savepoint(sid)  # type: ignore[misc]
        self._rls_at_savepoint[sid] = self.rls_applied_scope

    def _savepoint_rollback(self, sid: str) -> None:
        super()._savepoint_rollback(sid)  # type: ignore[misc]
        self.rls_applied_scope = self._rls_at_savepoint.get(sid)

    def _savepoint_commit(self, sid: str) -> None:
        super()._savepoint_commit(sid)  # type: ignore[misc]
        self._rls_at_savepoint.pop(sid, None)

    def _commit(self) -> None:
        try:
            super()._commit()  # type: ignore[misc]
        finally:
            self._rls_forget()

    def _rollback(self) -> None:
        try:
            super()._rollback()  # type: ignore[misc]
        finally:
            self._rls_forget()

    def _set_autocommit(self, autocommit: bool) -> None:
        super()._set_autocommit(autocommit)  # type: ignore[misc]
        self._rls_forget()

    def _close(self) -> None:
        try:
            super()._close()  # type: ignore[misc]
        finally:
            self._rls_forget()
