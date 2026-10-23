"""Facts shown on the landing page that cannot be read from the running code.

Everything else on the page (the role matrix, token lifetimes, throttle rates,
audit event names, live readiness) is rendered from settings and source at
request time. The test inventory below is pinned by
``tests/test_web.py::test_landing_test_inventory_matches_the_suite``, which
fails when the suite changes and this file does not.
"""

from __future__ import annotations

from typing import Final, NamedTuple


class SuiteFile(NamedTuple):
    path: str
    tests: int
    focus: str


TEST_SUITE: Final[tuple[SuiteFile, ...]] = (
    SuiteFile(
        "test_permissions_matrix.py",
        97,
        "The role table, executed for every role and for anonymous callers",
    ),
    SuiteFile(
        "test_tenant_isolation.py",
        79,
        "Cross-tenant matrix, foreign-key references, existence oracle, route coverage",
    ),
    SuiteFile(
        "test_sso.py",
        56,
        "OIDC with PKCE: each ID-token check attacked, no IdP crosses tenants",
    ),
    SuiteFile(
        "test_row_level_security.py",
        51,
        "Raw SQL past the ORM, no scope, a fresh connection: PostgreSQL still isolates",
    ),
    SuiteFile(
        "test_mfa.py",
        45,
        "TOTP against the RFC vectors, WebAuthn end to end, every replay refused",
    ),
    SuiteFile(
        "test_api_keys.py",
        39,
        "Keys for services: hashed, read-only, scoped per endpoint, one tenant only",
    ),
    SuiteFile(
        "test_web.py",
        36,
        "This page, the API docs, error pages and the Content Security Policy",
    ),
    SuiteFile(
        "test_privilege_escalation.py",
        32,
        "Mass assignment, self-promotion, last-admin invariant, forged tokens",
    ),
    SuiteFile(
        "test_login_throttling.py",
        27,
        "Per-account delays a botnet can't dodge and a stranger can't lock you out with",
    ),
    SuiteFile(
        "test_platform.py",
        24,
        "Health probes, OpenAPI schema, request IDs, JSON logs, secure settings",
    ),
    SuiteFile(
        "test_tasks.py",
        23,
        "The task queue and invitation email: outbox, scopes, retries, leases, idempotency",
    ),
    SuiteFile(
        "test_audit_chain.py",
        22,
        "Hash chains catch edits, deletions and reorders; partitions, retention, SIEM",
    ),
    SuiteFile(
        "test_auth.py",
        21,
        "Login auditing, spoof-proof throttling, logout everywhere, deactivation",
    ),
    SuiteFile(
        "test_sessions.py",
        21,
        "Refresh-token families: a replayed token ends the session, races have one winner",
    ),
    SuiteFile(
        "test_users_and_organizations.py",
        21,
        "Role changes, soft deactivation, database check constraints",
    ),
    SuiteFile(
        "test_account_recovery.py",
        16,
        "Password reset without enumeration, your sessions, signing a member out",
    ),
    SuiteFile(
        "test_invitations.py",
        15,
        "Lifecycle, expiry, single use, sign-up races, enumeration resistance",
    ),
    SuiteFile(
        "test_audit_log.py",
        13,
        "Immutability in the ORM and in the PostgreSQL trigger, filters",
    ),
    SuiteFile(
        "test_tracing.py",
        12,
        "Spans named by route with request and tenant IDs, one trace into the worker, no PII",
    ),
    SuiteFile(
        "test_admin.py",
        11,
        "The Django admin: throttled, audited, no live tokens, strict CSP",
    ),
)
