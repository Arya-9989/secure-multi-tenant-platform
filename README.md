<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/hero-dark.svg">
  <img alt="Secure Multi-Tenant Platform. Every tenant, sealed: Alice from Acme asks for a Globex user and gets 404, the same as a random ID. Fail-closed tenant isolation for Django REST Framework, proven by 274 tests." src="docs/hero-light.svg" width="100%">
</picture>

# Secure Multi-Tenant Platform

[![CI](https://github.com/Arya-9989/secure-multi-tenant-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/Arya-9989/secure-multi-tenant-platform/actions/workflows/ci.yml)
&nbsp;Python 3.12 · Django 6.0 · Django REST Framework · PostgreSQL 17 · [MIT](LICENSE)

A multi-tenant SaaS backend in Django REST Framework where **tenant isolation is enforced
centrally and then proven by tests**. Every tenant-scoped endpoint is attacked by a
parametrized suite (IDOR, cross-tenant writes, foreign-key references, privilege escalation,
forged tokens), and a structural test fails the build if someone adds a route without
covering it.

It includes three roles, token-based expiring invitations, soft deactivation, hardened JWT
sessions (rotation, blacklist, instant revocation) and an append-only audit log that
PostgreSQL itself refuses to modify.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/swagger-cross-tenant-404-dark.png">
  <img alt="Swagger UI: an Acme admin asks for a Globex user and gets 404" src="docs/screenshots/swagger-cross-tenant-404-light.png">
</picture>

<sub>An Acme admin, authorized in Swagger UI, asks for a Globex user's ID and gets `404`,
exactly what a nonexistent ID returns.</sub>

---

## Contents

- [Highlights](#highlights)
- [Landing page and API docs](#landing-page-and-api-docs)
- [Quickstart](#quickstart)
- [Architecture](#architecture)
- [Tenancy and security model](#tenancy-and-security-model)
- [Roles and permissions](#roles-and-permissions)
- [API overview](#api-overview)
- [Configuration](#configuration)
- [Testing](#testing)
- [Project structure](#project-structure)
- [Design decisions and trade-offs](#design-decisions-and-trade-offs)
- [Roadmap (future work)](#roadmap-future-work)

## Highlights

- **Central, fail-closed isolation.** One method, `TenantQuerySet.visible_to(user)`, decides
  which rows exist for a caller. `TenantScopedViewSet` applies it to every view and adds an
  object-level guard. Relation fields in request bodies are scoped too.
- **Declarative RBAC.** A single role→permission matrix (`apps/accounts/roles.py`). Views
  declare `required_permissions` per action; undeclared actions are denied.
- **Database-enforced invariants.** Check constraints guarantee that only super admins have
  no organization and only super admins are staff. Emails are lowercase. There is at most one
  open invitation per email per organization.
- **JWT sessions that can be killed.** 5-minute access tokens, rotating refresh tokens with a
  blacklist, logout, and logout-everywhere. Each request re-checks the user, the organization
  and a per-user `token_version` against the database. A refresh token is claimed atomically,
  so two requests racing with the same token can't both get a new session.
- **Append-only audit log.** It records who, what, which tenant, IP, user agent and request
  ID, written in the same transaction as the change. The model, its QuerySet and a
  PostgreSQL trigger all reject updates and deletes.
- **Production packaging.** Multi-stage, non-root Docker image running gunicorn with a
  healthcheck. Compose stack with Postgres and Redis. Structured JSON logs carry a request ID.
  Settings come from env vars with secure defaults.
- **A strict Content Security Policy on every response.** Django's built-in CSP middleware
  sends `default-src 'self'`, `script-src 'self'`, `object-src 'none'`, `base-uri 'none'` and
  `frame-ancestors 'none'`, with no `'unsafe-inline'` or `'unsafe-eval'` anywhere. The landing
  page, Swagger UI, Redoc, the error pages and the Django admin run with no inline scripts and
  no third-party requests.
- **Rate limits a client can't dodge.** Every throttle keys on the same client IP the audit
  log records, and `X-Forwarded-For` counts only behind `NUM_PROXIES` trusted proxies. The
  Django admin sign-in shares the API's credential limit and is audited the same way.

## Landing page and API docs

The service explains itself at `/`. The landing page is rendered by the app, and wherever it
can, it reads its facts from the running code instead of repeating them: the role matrix comes
from `ROLE_PERMISSIONS`, token lifetimes and the login throttle from settings, the audit event
names from `AuditAction`, and the status line from the same checks as `/health/ready/`. The
per-file test counts are pinned by `test_landing_test_inventory_matches_the_suite`, which fails
when the suite and the page disagree. The core content needs no JavaScript.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/landing-dark.png">
  <img alt="Landing page: Every tenant. Sealed. Acme Corp is Alice's tenant; Globex Inc is sealed from her." src="docs/screenshots/landing-light.png">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/landing-isolation-dark.png">
  <img alt="Landing page diagram: every request passes context, authentication, role authorization, row scoping, then the service layer and audit log; failures return 401, 403 or 404." src="docs/screenshots/landing-isolation-light.png">
</picture>

Swagger UI (`/api/docs/`) and Redoc (`/api/redoc/`) share the page's type, colours and light
and dark themes, which follow the operating system. Every asset is self-hosted: Swagger UI and
Redoc from `drf-spectacular-sidecar`, and the Inter and JetBrains Mono variable fonts (SIL Open
Font License) from `apps/web/static/web/fonts/`.

- **Swagger UI** keeps deep links: the open operation is mirrored in the URL, and opening that
  URL expands it again. A small plugin (`apps/web/static/web/js/swagger-plugins.js`) keeps
  that accessible, with no link nested inside an operation's toggle button, every region in a
  landmark and no skipped heading levels. The init script is served as a separate file.
- **Redoc** runs from a copy of the sidecar bundle with three exact edits, applied at request
  time (`REDOC_PATCHES` in `apps/web/views.py`): its attribution logo comes from this app
  instead of Redocly's CDN, section labels become `h3` instead of `h5`, and regex patterns
  use the theme's accent instead of a fixed teal that fails contrast in dark mode. Each edit
  must match exactly once, so an upgrade that changes the bundle fails the tests. Redoc
  injects its styles at runtime, so only its page adds a per-response style nonce, two pinned
  style hashes and `worker-src blob:` for the search index.
- **Errors** get pages in the same design: 404, 500 with the request ID to quote, 403 and
  CSRF failures, and 429 for a throttled admin sign-in. Under `/api/` they are JSON
  (`{"detail": "Not found."}`), like every other API response.
- **The Django admin** wears the same slate and teal in both themes, with the product mark,
  hit areas of at least 24px and no layout shift when its sidebar restores itself.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/redoc-dark.png">
  <img alt="Redoc, themed to match" src="docs/screenshots/redoc-light.png">
</picture>

## Quickstart

### Docker (production-like: gunicorn + PostgreSQL + Redis)

```bash
docker compose up --build -d --wait
docker compose exec api python manage.py seed_demo --force
open http://localhost:8000/                 # landing page (Swagger UI: /api/docs/, Redoc: /api/redoc/)
```

`seed_demo` creates two tenants so you can try the isolation right away. All accounts use
the password `Demo-Passw0rd!2026`:

| Email | Role | Organization |
|---|---|---|
| `root@platform.test` | SUPER_ADMIN | (none, platform operator) |
| `alice@acme.test` | ORG_ADMIN | Acme Corp |
| `bob@acme.test` | MEMBER | Acme Corp |
| `grace@globex.test` | ORG_ADMIN | Globex Inc |
| `gus@globex.test` | MEMBER | Globex Inc |

> `--force` is required because the container runs with `DEBUG=False`. The command refuses to
> seed known passwords into a production-mode database otherwise.

### Local (uv + SQLite)

```bash
uv sync                          # Python 3.12, dependencies pinned in uv.lock
cp .env.example .env             # DEBUG on, HTTPS redirects off, console logs
uv run python manage.py migrate
uv run python manage.py seed_demo
uv run python manage.py runserver
```

### See the isolation in 30 seconds

```bash
API=http://localhost:8000/api/v1
login() { curl -s -X POST $API/auth/login/ -H 'Content-Type: application/json' \
  -d "{\"email\":\"$1\",\"password\":\"Demo-Passw0rd!2026\"}" | jq -r .access; }
ALICE=$(login alice@acme.test); GRACE=$(login grace@globex.test)
GRACE_ID=$(curl -s $API/auth/me/ -H "Authorization: Bearer $GRACE" | jq -r .id)

curl -s $API/users/ -H "Authorization: Bearer $ALICE" | jq '[.results[].email]'
# ["alice@acme.test", "bob@acme.test"]          <- only Acme

curl -s -w ' %{http_code}\n' $API/users/$GRACE_ID/ -H "Authorization: Bearer $ALICE"
# {"detail":"No User matches the given query."} 404   <- Globex does not exist for Alice
```

## Architecture

```mermaid
flowchart LR
    client([API client]) -->|HTTPS| proxy[TLS proxy / LB]
    proxy --> gunicorn

    subgraph app [Django app - gunicorn workers]
        direction TB
        mw["RequestContextMiddleware<br/>request ID - client IP - access log"]
        auth["TenantJWTAuthentication<br/>signature - aud/iss - token_version<br/>user + org active"]
        perms["HasRolePermission<br/>role → permission matrix"]
        scope["TenantQuerySet.visible_to(user)<br/>+ TenantObjectPermission"]
        svc["Service layer<br/>re-checks perm + tenant<br/>row locks - invariants"]
        audit["audit.record()<br/>same transaction"]
        mw --> auth --> perms --> scope --> svc --> audit
    end

    gunicorn --> mw
    svc --> pg[(PostgreSQL<br/>check constraints<br/>append-only trigger)]
    audit --> pg
    perms -. throttle counters .-> redis[(Redis)]
    mw -. JSON logs .-> stdout[[stdout]]
```

| App | Responsibility |
|---|---|
| `apps.common` | Tenancy primitives, RBAC permission classes, strict serializers, request context, JSON logging, health probes, OpenAPI error docs |
| `apps.organizations` | Tenants (`Organization`) and their lifecycle |
| `apps.accounts` | Users, roles, JWT auth, sessions, invitations, `seed_demo` |
| `apps.auditlogs` | Append-only `AuditLog`, the `record()` service, and the query API |

### Request and authorization flow

```mermaid
sequenceDiagram
    autonumber
    actor A as Alice (ORG_ADMIN, Acme)
    participant MW as RequestContext
    participant JWT as TenantJWTAuthentication
    participant RBAC as HasRolePermission
    participant QS as visible_to(user)
    participant S as Service
    participant DB as PostgreSQL

    A->>MW: POST /api/v1/users/{id}/deactivate/ (Bearer token)
    MW->>MW: bind request_id, client IP
    MW->>JWT: authenticate
    JWT->>DB: load user + organization
    alt bad signature / expired / blacklisted / stale token_version / inactive
        JWT-->>A: 401
    end
    JWT->>RBAC: role ORG_ADMIN needs user:manage
    alt role lacks permission
        RBAC-->>A: 403
    end
    RBAC->>QS: User.objects.filter(organization=Acme).get(pk=id)
    alt row belongs to another tenant (or does not exist)
        QS-->>A: 404 (indistinguishable)
    end
    QS->>S: deactivate_user(actor, target)
    S->>DB: BEGIN, lock org row, then user row
    S->>S: re-check permission + tenant, not self, not last admin
    S->>DB: update user, bump token_version, blacklist refresh tokens
    S->>DB: INSERT audit_log (actor, tenant, IP, request_id)
    S->>DB: COMMIT
    S-->>A: 200 + X-Request-ID
```

## Tenancy and security model

**Model:** a shared database and shared schema. Every tenant-owned row carries an
`organization` foreign key. Users belong to exactly one organization. Super admins belong to
none, and the database enforces both rules.

### Isolation guarantees

1. **No cross-tenant reads.** A tenant user never receives rows owned by another
   organization, through detail routes, list routes, filters (`?organization=`) or search.
2. **No cross-tenant writes.** Mutations on foreign objects fail before any state changes,
   and the tests assert the row is byte-for-byte unchanged.
3. **No existence oracle.** A foreign ID gets the same `404` response body as a random UUID.
   A foreign ID in a request body (for example `organization` on an invitation) gets the same
   "does not exist" error.
4. **No vertical escalation over HTTP.** `SUPER_ADMIN` cannot be assigned through the API.
   Organization membership is immutable. Unknown or read-only fields (`role` on `/me`,
   `organization`, `is_staff`, ...) are rejected with `400` instead of being silently
   ignored.
5. **Fail-closed by construction.** Anonymous, inactive or org-less callers see nothing.
   Undeclared actions are denied. A view whose queryset is not tenant-aware raises
   `ImproperlyConfigured`.

### Threat model

| Threat | Mitigation | Proven by |
|---|---|---|
| IDOR: read or modify another tenant's object by ID | `visible_to()` in `TenantScopedViewSet.get_queryset`, `TenantObjectPermission` as a backstop, services re-check the tenant | `test_tenant_isolation.py::test_cross_tenant_object_access_is_denied` (10 endpoints × 2 roles) |
| Leaks through list endpoints, filters or search | Scoping is applied before filter backends | `test_list_endpoints_never_return_foreign_rows` |
| IDOR through foreign keys in request bodies | `TenantScopedPrimaryKeyRelatedField` resolves only visible objects | `test_cannot_invite_into_another_tenant_by_reference` |
| Privilege escalation (`role=SUPER_ADMIN`, moving orgs, `is_staff`) | Strict serializers, assignable-roles allow-list, DB check constraints, no self-modification | `test_privilege_escalation.py` (mass assignment, self-promotion, `/me` tampering) |
| Orphaning a tenant (removing its last admin) | Invariant checked under row locks (org → user lock order) | `test_last_active_org_admin_cannot_be_removed` |
| Forged or tampered JWTs, `alg=none` or another algorithm, wrong `aud`/`iss`, refresh used as access | SimpleJWT verification pinned to HS256, with audience and issuer, ≥32-char key enforced at startup | `test_forged_or_invalid_tokens_are_rejected` (9 variants) |
| Trusting role or tenant claims in a token | Authorization reads role and tenant from the DB on every request | `test_role_claims_in_token_are_ignored` |
| Refresh-token replay, stolen sessions | Rotation plus blacklist, claimed atomically so racing requests can't both redeem one token. Logout, logout-all, `token_version` bump on password change or deactivation | `test_auth.py` (rotation, logout, logout-all, password change), `test_a_refresh_token_is_redeemed_once_even_when_requests_race` |
| Deactivated user or org keeps working until token expiry | User and org `is_active` checked on every request and refresh. Deactivating an org revokes its members' tokens, so reactivating it doesn't revive old sessions | `test_deactivation_takes_effect_on_the_next_request`, `test_deactivating_an_organization_cuts_off_live_sessions`, `test_reactivating_an_organization_does_not_revive_old_sessions` |
| Credential brute force | 10/min per-client throttle on API login, admin sign-in, refresh, password change and invitation accept, plus audited failures | `test_login_is_throttled`, `test_admin_login_is_throttled_like_the_api` |
| Dodging the rate limit with a forged `X-Forwarded-For` | Throttles key on the audited client IP (`get_client_ip`), which ignores the header unless `NUM_PROXIES` > 0 and then takes the address the outermost trusted proxy appended | `test_login_throttle_ignores_a_spoofed_forwarded_for`, `test_behind_a_trusted_proxy_the_throttle_keys_on_the_address_it_appended` |
| Account enumeration | One generic login error. Invitation acceptance fails generically, including when another sign-up takes the address mid-request. Inviting an email registered in another tenant reveals nothing | `test_failed_logins_are_generic_and_audited`, `test_no_cross_tenant_email_enumeration`, `test_a_signup_race_for_the_same_email_fails_generically` |
| Invitation tokens leaked from the DB | Only a SHA-256 digest is stored. Tokens are single-use and expire after 72h | `test_invitation_lifecycle`, `test_unusable_tokens_fail_generically` |
| Audit tampering | Model, QuerySet (including `bulk_create` upserts) and admin are read-only. A PostgreSQL `BEFORE UPDATE OR DELETE` trigger blocks raw SQL. Actors with history cannot be hard-deleted (`PROTECT`) | `test_audit_log.py` (incl. `test_database_trigger_rejects_raw_sql_mutation`, `test_bulk_create_cannot_upsert_over_existing_entries`) |
| The Django admin as a side door | Sign-in throttled and audited like the API. Logging out everywhere, deactivation and an admin password change end admin sessions and API tokens alike. Stored refresh tokens are never displayed and blacklist entries can't be deleted. Tenant changes go through the audited services, and tenants can't be deleted | `test_admin.py` |
| Spoofed client IP or log injection | `X-Forwarded-For` is trusted only with `NUM_PROXIES` > 0. Caller request IDs must match `[A-Za-z0-9._-]{8,64}` | `test_client_ip_trusts_only_configured_proxies`, `test_request_id_is_propagated_or_generated` |
| Injected script or framing on the landing page, API docs, error pages and admin | A strict CSP on every response: scripts, styles and fonts from the app's own origin only, no `'unsafe-inline'`, `frame-ancestors 'none'`. The pages contain no inline code and make no third-party requests | `test_web.py::test_strict_content_security_policy_on_every_response`, `test_pages_need_no_inline_code_or_third_party_assets`, `test_redoc_runs_a_self_hosted_bundle_that_makes_no_third_party_requests`, `test_admin.py::test_every_admin_page_works_under_the_strict_csp` |
| A new endpoint ships without isolation | Structural tests: every API route must be in the isolation suite, every router viewset must subclass `TenantScopedViewSet`, every action must declare a permission | `test_every_api_route_is_covered`, `test_every_routed_viewset_is_tenant_scoped_and_declares_permissions` |

**Explicitly out of scope / residual risk**

- Isolation is enforced in the application. Raw SQL written by a developer bypasses it, and
  there is no PostgreSQL row-level security yet (see roadmap).
- After a *single-session* logout, that session's access token stays valid for up to 5
  minutes. Use logout-all when that matters, since it revokes access tokens immediately.
- Without `REDIS_URL`, throttle counters are kept per gunicorn worker, so the effective limit
  is multiplied by the worker count. The compose stack uses Redis.
- The table owner can still `TRUNCATE` or drop the audit table. In production, run the app
  under a role that does not own the schema.

## Roles and permissions

`SUPER_ADMIN` operates the platform. `ORG_ADMIN` administers one organization. `MEMBER` is a
regular user. Rows are always limited to the caller's own organization, except for super
admins.

| Capability | Endpoint(s) | SUPER_ADMIN | ORG_ADMIN | MEMBER |
|---|---|:-:|:-:|:-:|
| View organizations | `GET /organizations/`, `GET /organizations/{id}/` | all | own | own |
| Create / update organizations | `POST /organizations/`, `PATCH /organizations/{id}/` | yes | no | no |
| View users | `GET /users/`, `GET /users/{id}/` | all | own org | own org |
| Change role (ORG_ADMIN ⇄ MEMBER) | `PATCH /users/{id}/` | yes | own org | no |
| Deactivate / reactivate users | `POST /users/{id}/deactivate/`, `.../reactivate/` | yes | own org | no |
| Manage invitations | `GET/POST /invitations/`, `POST /invitations/{id}/revoke/` | any org | own org | no |
| Query audit log | `GET /audit-logs/`, `GET /audit-logs/{id}/` | all + platform events | own org | no |
| Own profile and sessions | `/auth/me/`, `/auth/password/change/`, `/auth/logout*/` | yes | yes | yes |

Guard rails that apply to every role: nobody can change their own role or status, super
admin accounts can't be managed over HTTP (use `createsuperuser`), and an organization
always keeps at least one active `ORG_ADMIN`. The matrix is executed by
`tests/test_permissions_matrix.py` and pinned by `test_role_matrix_shape`.

## API overview

All endpoints live under `/api/v1/`. The landing page is at `/`, the interactive docs are at
`/api/docs/` (Swagger UI) and `/api/redoc/`, and the schema is at `/api/schema/`. Every
response carries an `X-Request-ID` header and a `Content-Security-Policy` header, and errors
under `/api/`, including unknown routes, are JSON.

| Area | Endpoints |
|---|---|
| Auth | `POST auth/login/` · `POST auth/refresh/` · `POST auth/logout/` · `POST auth/logout-all/` · `GET/PATCH auth/me/` · `POST auth/password/change/` |
| Organizations | `GET/POST organizations/` · `GET/PATCH organizations/{id}/` |
| Users | `GET users/` (`?role=`, `?is_active=`, `?search=`) · `GET/PATCH users/{id}/` · `POST users/{id}/deactivate/` · `POST users/{id}/reactivate/` |
| Invitations | `GET/POST invitations/` (`?status=pending\|accepted\|revoked\|expired`) · `GET invitations/{id}/` · `POST invitations/{id}/revoke/` · `POST invitations/accept/` (public) |
| Audit log | `GET audit-logs/` (`?action=`, `?actor=`, `?target_id=`, `?request_id=`, `?created_after=`, `?created_before=`, cursor-paginated) · `GET audit-logs/{id}/` |
| Health | `GET /health/live/` · `GET /health/ready/` (database + cache, `503` when degraded) |

```bash
API=http://localhost:8000/api/v1
TOKENS=$(curl -s -X POST $API/auth/login/ -H 'Content-Type: application/json' \
  -d '{"email":"alice@acme.test","password":"Demo-Passw0rd!2026"}')
ACCESS=$(echo "$TOKENS" | jq -r .access); REFRESH=$(echo "$TOKENS" | jq -r .refresh)
AUTH="Authorization: Bearer $ACCESS"

# Invite a colleague (the raw token is returned once and emailed; only its hash is stored)
curl -s -X POST $API/invitations/ -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"email":"carol@acme.test","role":"MEMBER"}' | jq '{id, status, expires_at, token}'

# Accept it (public endpoint, throttled; password validators apply)
curl -s -X POST $API/invitations/accept/ -H 'Content-Type: application/json' \
  -d '{"token":"<token>","password":"A-Strong-Passphrase-1","full_name":"Carol"}'

# Promote, then try to escalate (rejected with 400)
curl -s -X PATCH $API/users/<carol-id>/ -H "$AUTH" -H 'Content-Type: application/json' -d '{"role":"ORG_ADMIN"}'
curl -s -X PATCH $API/users/<carol-id>/ -H "$AUTH" -H 'Content-Type: application/json' -d '{"role":"SUPER_ADMIN"}'

# Query the audit trail for your tenant
curl -s "$API/audit-logs/?action=user.role_changed&page_size=5" -H "$AUTH" \
  | jq '.results[] | {created_at, action, actor_email, metadata, ip_address, request_id}'

# Rotate the refresh token (the old one is blacklisted), then log out everywhere
curl -s -X POST $API/auth/refresh/ -H 'Content-Type: application/json' -d "{\"refresh\":\"$REFRESH\"}"
curl -s -X POST $API/auth/logout-all/ -H "$AUTH" -o /dev/null -w '%{http_code}\n'   # 204
```

Audit events: `auth.login_succeeded`, `auth.login_failed`, `auth.logout`, `auth.logout_all`,
`auth.password_changed`, `organization.created`, `organization.updated`,
`user.profile_updated`, `user.role_changed`, `user.deactivated`, `user.reactivated`,
`invitation.created`, `invitation.revoked`, `invitation.accepted`.

## Configuration

All settings come from environment variables (or `.env` locally, see
[`.env.example`](.env.example)). The defaults are safe for production. Development opts out
of them explicitly.

| Variable | Default | Purpose |
|---|---|---|
| `DJANGO_SECRET_KEY` | *(required unless `DJANGO_DEBUG=True`)* | Django secret; startup fails if unset in production |
| `DJANGO_DEBUG` | `False` | Debug mode |
| `DJANGO_ALLOWED_HOSTS` | `[]` (`localhost,127.0.0.1` in debug) | Comma-separated hosts. Include `localhost` for the container healthcheck |
| `DATABASE_URL` | `sqlite:///db.sqlite3` | Any `dj-database-url` style URL; PostgreSQL in production |
| `DATABASE_CONN_MAX_AGE` | `60` | Persistent connection lifetime (seconds) |
| `REDIS_URL` | *(unset → in-process cache)* | Shared cache for throttling across workers |
| `JWT_SIGNING_KEY` | `DJANGO_SECRET_KEY` | HS256 key, ≥ 32 characters (enforced) |
| `JWT_ACCESS_TTL_MINUTES` / `JWT_REFRESH_TTL_DAYS` | `5` / `1` | Token lifetimes |
| `JWT_AUDIENCE` / `JWT_ISSUER` | `secure-multi-tenant-platform` | `aud` / `iss` claims (verified) |
| `PASSWORD_MIN_LENGTH` | `12` | Plus Django's similarity, common-password and numeric validators |
| `INVITATION_TTL_HOURS` | `72` | Invitation expiry |
| `FRONTEND_INVITE_URL` | `http://localhost:3000/accept-invite?token={token}` | Link placed in invitation emails |
| `EMAIL_BACKEND` / `DEFAULT_FROM_EMAIL` | console / `no-reply@localhost` | Email delivery |
| `THROTTLE_AUTH` / `THROTTLE_ANON` / `THROTTLE_USER` | `10/min` / `60/min` / `600/min` | Rate limits |
| `NUM_PROXIES` | `0` | Trusted proxies in front of the app. Decides the client IP for the audit log and for every rate limit |
| `DJANGO_BEHIND_TLS_PROXY` | `False` | Trust `X-Forwarded-Proto: https` |
| `DJANGO_SECURE_SSL_REDIRECT` / `DJANGO_SECURE_COOKIES` | `True` (when not debug) | HTTPS redirect, secure cookies |
| `DJANGO_SECURE_HSTS_SECONDS` / `DJANGO_SECURE_HSTS_PRELOAD` | `31536000` / `False` | HSTS |
| `DJANGO_ADMIN_URL` | `admin/` | Django admin path. Super admins only; read-only except creating and editing tenants, which goes through the audited services |
| `API_DOCS_ENABLED` | `True` | Serve `/api/docs/`, `/api/redoc/`, `/api/schema/` (the landing page at `/` is always served and links to them only when enabled) |
| `LOG_FORMAT` / `LOG_LEVEL` | `json` / `INFO` | `json` or `console` |
| `GUNICORN_WORKERS` / `GUNICORN_THREADS` / `PORT` | `min(2·CPU+1, 8)` / `2` / `8000` | Server sizing |

## Testing

```bash
uv run pytest --cov                                   # SQLite: trigger tests are skipped
DATABASE_URL=postgres://app:app@localhost:5432/app uv run pytest --cov   # what CI runs
uv run ruff check . && uv run ruff format --check . && uv run mypy .
```

The suite has 274 tests and 97% branch coverage (the gate is 90%). It runs against
PostgreSQL in CI.

| File | Focus |
|---|---|
| `test_tenant_isolation.py` | Cross-tenant matrix (object and list endpoints, FK references, existence oracle) plus structural coverage guards |
| `test_permissions_matrix.py` | The roles table above, executed for every role, and anonymous access |
| `test_privilege_escalation.py` | Mass assignment, self-promotion, super-admin protection, last-admin invariant, forged tokens |
| `test_auth.py` | Login auditing, rotation and blacklist (including racing refreshes), logout(-all), deactivation and reactivation, throttling that a forged `X-Forwarded-For` can't dodge, password change |
| `test_invitations.py` | Lifecycle, expiry, revocation, single use, weak passwords, sign-up races, enumeration resistance |
| `test_audit_log.py` | Immutability (ORM, bulk upserts and PostgreSQL trigger), context capture, filters, cursor pagination |
| `test_admin.py` | The Django admin: throttled and audited sign-in, sessions that end with logout-all and password changes, stored tokens never shown, no un-revoking, audited tenant changes, every page under the strict CSP |
| `test_users_and_organizations.py` | Role changes, soft deactivation, slugs, uniqueness, DB check constraints |
| `test_platform.py` | Health probes, OpenAPI schema (zero warnings, validated), request IDs, JSON logs, secure settings, `seed_demo` |
| `test_web.py` | Landing page facts rendered from code, degraded status, no inline code or third-party assets, the CSP on every response, Swagger deep links and plugin order, the patched Redoc bundle, error pages (HTML and JSON), and the landing page's test inventory |

CI (`.github/workflows/ci.yml`) has four jobs. **lint** runs ruff, mypy (strict, with
django-stubs and DRF stubs), the migration drift check and `check --deploy`. **test** runs
pytest against a PostgreSQL 17 service with a coverage report. **audit** runs pip-audit over
the hash-pinned lockfile export. **docker** builds the image, boots the compose stack and
runs a cross-tenant smoke test against gunicorn.

## Project structure

```
.
├── apps/
│   ├── common/          # tenancy.py, permissions.py, views.py (TenantScopedViewSet, health),
│   │                    # middleware.py, logging.py, serializers.py (strict), guards.py, schema.py,
│   │                    # throttling.py (client-IP rate limits), admin_site.py (hardened admin)
│   ├── web/             # landing page at /, themed Swagger UI + Redoc, error pages, admin theme,
│   │                    # CSS/JS, self-hosted fonts
│   ├── organizations/   # Organization model, service, viewset
│   ├── accounts/        # User + Invitation models, roles.py (RBAC matrix), authentication.py,
│   │   ├── serializers/ # services.py (business rules), views/, management/commands/seed_demo.py
│   │   └── views/
│   └── auditlogs/       # AuditLog model, record() service, read-only API,
│       └── migrations/  # 0002_append_only_trigger.py
├── config/              # settings.py (env-driven), test_settings.py, urls.py, wsgi/asgi
├── tests/               # pytest-django suite (see table above)
├── docs/                # README hero (light/dark SVG) and screenshots/
├── Dockerfile           # multi-stage, non-root, gunicorn, HEALTHCHECK
├── docker-compose.yml   # api + migrate + postgres + redis
├── gunicorn.conf.py
├── pyproject.toml       # deps, ruff, mypy, pytest, coverage config
└── uv.lock
```

## Design decisions and trade-offs

**Shared schema vs schema-per-tenant vs database-per-tenant.** I chose a shared schema with
an `organization` FK. It keeps migrations, connection pooling, cross-tenant operator queries
and analytics simple, and it scales to many small tenants. The cost is that isolation lives
in code, so the code path is centralized and backed by an adversarial test suite. Schema-per-tenant
(for example `django-tenants`) gives stronger blast-radius isolation and per-tenant
restore, but migrations grow O(tenants) and pooling gets harder. Database-per-tenant fits
few, large, regulated tenants. PostgreSQL row-level security is the natural next layer
without changing the model.

**Explicit `visible_to(user)` instead of a thread-local "current tenant" manager.**
Auto-filtering default managers look elegant, but they fail *open* when the context is
missing (background jobs, shell, tests) and they surprise people in admin and migrations.
An explicit call that returns `none()` for anything unexpected fails *closed*. The base
viewset makes it impossible to forget, and the structural tests make it impossible to bypass
silently.

**404 rather than 403 for foreign objects.** A 403 confirms that the ID exists. Scoping
makes foreign rows invisible, so they 404 like random IDs. A 403 is reserved for "your role
cannot do this at all", which leaks nothing about other tenants.

**Token version plus blacklist instead of stateful sessions.** JWTs stay stateless for
signature and expiry checks, but each request loads the user row anyway (it must, so that
role and tenant come from the DB and never from claims). Comparing one integer there makes
logout-all, password change and deactivation take effect immediately, at the cost of one
indexed lookup per request.

**Domain audit events instead of logging every HTTP request.** Every request already produces a
structured access-log line on stdout. The audit table stores *meaning* (`user.role_changed`
from `MEMBER` to `ORG_ADMIN`), written in the same transaction as the change, so it never
records something that rolled back.

**Invitations as the only way in.** There is no `POST /users/`. Onboarding always goes
through an expiring, single-use, hashed token, so admins never handle passwords. Super
admins are created out of band (`createsuperuser`), so no HTTP path can mint one.

**Immutable membership.** Users can't be moved between organizations. Moving them would
carry history, sessions and audit attribution across a tenant boundary. Deactivating and
re-inviting is explicit and auditable.

**Rate limits keyed on the audited client IP.** DRF's stock throttles trust `X-Forwarded-For`
whenever `NUM_PROXIES` is unset, so a client could rotate the header to reset its budget. One
function, `get_client_ip`, now decides who the client is for the audit log and for every
throttle, so the two can't disagree.

**Editing the vendored Redoc bundle instead of allowing a CDN.** Redoc loads its logo from
Redocly's CDN. Allowing that origin would break the "no third-party requests" rule and send
Redocly a request on every page view. The app serves the sidecar bundle with exact,
version-checked string edits instead, under a digest URL that caches forever.

**Cursor pagination for the audit log.** It is append-only and grows without bound. Cursor
pagination is stable under concurrent inserts and avoids `OFFSET` scans.

**Migrations were regenerated.** The original prototype's migrations were replaced because
the model changed fundamentally (UUID keys, constraints, new tables). Existing databases from
the prototype are not upgradable in place.

## Roadmap (future work)

None of these are implemented yet.

- PostgreSQL row-level security policies keyed on a per-transaction tenant setting, as a
  second, database-enforced isolation layer.
- Refresh-token families with reuse detection, revoking the whole family when a rotated
  token is replayed.
- Per-account login throttling with progressive delays, alongside the per-IP limit.
- MFA (TOTP/WebAuthn) and SSO via OIDC/SAML for organization admins.
- Audit log streaming to a SIEM, time-based partitioning and retention, and hash-chaining
  for tamper evidence beyond the database.
- Asynchronous email delivery (task queue plus provider) with delivery status on invitations.
- Scoped API keys for service-to-service access.
- OpenTelemetry tracing correlated with the existing request IDs.

## License

[MIT](LICENSE) © Arya Mahindrakar
