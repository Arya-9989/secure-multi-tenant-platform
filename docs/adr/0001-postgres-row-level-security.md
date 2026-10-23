# ADR 0001: PostgreSQL row-level security as a second isolation layer

- Status: accepted
- Date: 2026-10-23

## Context

Tenant isolation is enforced in the application: `TenantQuerySet.visible_to(user)` decides
which rows exist for a caller, `TenantScopedViewSet` applies it to every view, and a
structural test fails the build when a route is not covered by the isolation suite. That is
a single layer. A developer who writes `User.objects.all()` in a new code path, a raw SQL
report, or a background job that forgets the filter can read or modify every tenant's rows,
and nothing below the application would notice.

PostgreSQL row-level security (RLS) can enforce the same rule inside the database, so that a
missed filter returns nothing instead of another tenant's data. Three facts shape the design:

1. RLS does not apply to superusers or roles with `BYPASSRLS`, and it does not apply to a
   table's owner unless the table has `FORCE ROW LEVEL SECURITY`.
2. A policy needs to know the current tenant. The usual carrier is a custom setting such as
   `app.tenant_id`, set per transaction with `SET LOCAL` (or `set_config(..., true)`) so it
   cannot leak into the next request on a pooled connection.
3. Some code paths legitimately run before the tenant is known (login, token refresh,
   invitation acceptance) or across tenants (super admins, operator commands).

## Options considered

**A. Middleware opens one transaction per request and sets the tenant once.** Simple, but it
changes the transaction semantics of every endpoint, it cannot cover the queries that run
before authentication has decided the tenant, and it does nothing for management commands,
shells or task workers.

**B. Session-level `SET app.tenant_id` on every checkout.** Breaks under transaction-mode
connection poolers (PgBouncer) and leaks the previous request's tenant if a reset is ever
missed.

**C. A database backend that applies the scope to every statement (chosen).** The current
scope lives in a `ContextVar`. A subclass of Django's PostgreSQL backend runs
`set_config('app.tenant_id', ..., true)` inside the transaction before the first data
statement, and again whenever the scope changes or a savepoint rollback has reverted it. A
data statement issued outside a transaction is run inside a short transaction of its own so
that the transaction-local setting applies to exactly that statement. Whatever issues the
query (a view, a service, a management command, a worker), the database sees the scope that
the code is running under, and with no scope it sees nothing.

**D. Schema-per-tenant or database-per-tenant.** Stronger blast-radius isolation, but it is a
different data model with O(tenants) migrations. Out of scope for this item; the trade-off is
discussed in the README.

## Decision

### Scopes

Every statement runs under exactly one scope, carried in two transaction-local settings:

| Scope | `app.tenant_id` | `app.platform` | Sees |
|---|---|---|---|
| none (default) | empty | empty | nothing tenant-owned |
| tenant | the organization UUID | empty | that organization's rows |
| platform | empty | `on` | everything |

Policies call two small SQL functions, `app_current_tenant()` and `app_platform_access()`.
A missing or empty setting yields `NULL` and `false`, so a statement that runs without a scope
matches no rows and every write fails its `WITH CHECK`: the database fails closed. A
malformed tenant value fails the cast and the statement errors.

### Who sets the scope

- **Requests** start with no scope (`RequestContextMiddleware`). Authentication binds the
  caller's scope once the caller is known: the tenant for organization users, platform for
  super admins.
- **Pre-authentication lookups** (login, refresh, admin session, invitation acceptance)
  resolve the target account's tenant in a short, explicit platform block that returns only
  the tenant ID (`apps.accounts.scopes`). The rest of the flow runs in that tenant's scope.
  A failed login against an unknown email is recorded as a platform-level audit event, the
  only write that needs platform scope before authentication.
- **Management commands** run with no scope unless they ask. `seed_demo` uses an explicit
  platform block; an operator can start any other command with `APP_DB_SCOPE=platform`
  (read only by `manage.py`, never by the WSGI app).
- **Background tasks** (later items) run in the tenant recorded on the task.

### Policies

| Table | Read | Write |
|---|---|---|
| `organizations_organization` | own row (`id`) | platform only. Tenants may `SELECT ... FOR UPDATE` their own row (the service layer locks it), but the `WITH CHECK` refuses any change |
| `accounts_user`, `accounts_invitation` | own organization | own organization, and a row cannot be moved to another tenant |
| `auditlogs_auditlog` | own organization; platform-level rows only with platform scope | insert into own organization; no update or delete policy at all |

Every policy-bearing table has both `ENABLE` and `FORCE ROW LEVEL SECURITY`, so the owner is
subject to the policies too. A structural test fails the build if a model built on
`TenantQuerySet` has a table without RLS, without `FORCE`, or without a policy.

### Roles

- **Owner** (`app_owner` in compose and CI): owns the schema and runs migrations. It is not a
  superuser. Because of `FORCE`, even the owner sees no tenant rows unless it sets a scope.
- **Runtime** (`app_runtime`): what the API connects as. It is not the owner, not a superuser
  and has no `BYPASSRLS`. The first migration grants it `SELECT, INSERT, UPDATE, DELETE` on
  the schema's tables (and the same for future tables through default privileges), then takes
  away `UPDATE`, `DELETE` and `TRUNCATE` on the audit log and writes to `django_migrations`.
  `manage.py grant_runtime_role` re-applies the grants if the role is created later.
- With `DATABASE_REQUIRE_RLS=True` (the default when `DEBUG` is off), every new connection
  checks that its role is subject to RLS (not a superuser, no `BYPASSRLS`, does not own an
  RLS-protected table) and refuses to work otherwise. Migration and operator containers set
  it to `False` because they connect as the owner.

## Consequences

- Isolation is now enforced twice. The application layer keeps giving the precise answers
  (`404` for a foreign ID, "does not exist" for a foreign reference); RLS turns a forgotten
  filter into an empty result or a refused write instead of a leak. Tests prove it with raw
  SQL that bypasses the ORM entirely (`tests/test_row_level_security.py`), and the whole
  suite runs as the runtime role, so every existing test also proves the application works
  with RLS enforced.
- **Cost.** One extra `set_config` round trip per transaction, and a statement issued outside
  a transaction becomes `BEGIN`, `set_config`, the statement, `COMMIT`. The service layer
  already groups related writes in transactions; reads issued on their own pay the extra
  round trips. This is measurable but small next to the per-request user lookup, and it is
  the price of not depending on a session-level setting.
- **What RLS does not defend against.** The settings are chosen by the application, so code
  that can run arbitrary SQL as the runtime role (SQL injection, a compromised process) can
  also set `app.platform`. RLS here protects against mistakes, not against an attacker who
  already executes SQL; parameterised ORM queries remain the defence against injection. A
  role-switching design (`SET ROLE` to a `BYPASSRLS` role for platform work) was considered
  and rejected for the same reason: `SET ROLE` is just as available to injected SQL.
- **Uniqueness still crosses tenants.** Unique indexes are not filtered by RLS, so an insert
  that collides with another tenant's email fails with an integrity error. The invitation flow
  already turns that into its generic "invalid invitation" answer, so it reveals nothing.
- SQLite (local development without Docker) has no RLS; the scope bookkeeping still runs but
  the database enforces nothing. CI and the compose stack use PostgreSQL.
