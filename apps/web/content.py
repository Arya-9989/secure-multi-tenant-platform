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
        61,
        "The role table, executed for every role and for anonymous callers",
    ),
    SuiteFile(
        "test_tenant_isolation.py",
        48,
        "Cross-tenant matrix, foreign-key references, existence oracle, route coverage",
    ),
    SuiteFile(
        "test_privilege_escalation.py",
        31,
        "Mass assignment, self-promotion, last-admin invariant, forged tokens",
    ),
    SuiteFile(
        "test_platform.py",
        24,
        "Health probes, OpenAPI schema, request IDs, JSON logs, secure settings",
    ),
    SuiteFile(
        "test_users_and_organizations.py",
        21,
        "Role changes, soft deactivation, database check constraints",
    ),
    SuiteFile(
        "test_auth.py",
        18,
        "Rotation and blacklist, logout everywhere, deactivation, throttling",
    ),
    SuiteFile(
        "test_web.py",
        14,
        "This page and the themed API docs: facts from code, no inline code",
    ),
    SuiteFile(
        "test_invitations.py",
        14,
        "Lifecycle, expiry, single use, enumeration resistance",
    ),
    SuiteFile(
        "test_audit_log.py",
        11,
        "Immutability in the ORM and in the PostgreSQL trigger, filters",
    ),
)
