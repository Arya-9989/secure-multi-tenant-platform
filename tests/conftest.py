from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import jwt
import pytest
from django.conf import settings
from django.core.cache import cache
from django.db import connection, connections, transaction
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts import sessions
from apps.accounts.authentication import FAMILY_CLAIM
from apps.accounts.models import Invitation, User, hash_invitation_token
from apps.accounts.roles import Role
from apps.apikeys.models import ApiKey, hash_secret
from apps.auditlogs.models import AuditAction, AuditLog
from apps.auditlogs.services import record
from apps.common import crypto, rls
from apps.common.rls_migrations import runtime_role
from apps.organizations.models import Organization
from apps.sso.models import OidcProvider

PASSWORD = "Correct-Horse-Battery-9"
POSTGRES = connection.vendor == "postgresql"


# ---------------------------------------------------------------- row-level security
# On PostgreSQL the suite builds the test database as the owner, then runs every
# test as the runtime role (Django's ``assume_role``), so the whole suite proves
# that the application works with row-level security enforced (ADR 0001).
@pytest.fixture(scope="session")
def _runtime_role(django_db_blocker: Any) -> str:
    role = runtime_role()
    if not POSTGRES:
        return role
    with django_db_blocker.unblock(), connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [role])
        if cursor.fetchone() is None:
            quoted = connection.ops.quote_name(role)
            try:
                cursor.execute(f"CREATE ROLE {quoted} NOLOGIN NOSUPERUSER NOBYPASSRLS")
                cursor.execute(f"GRANT {quoted} TO CURRENT_USER")
            except Exception as exc:  # pragma: no cover - environment problem
                pytest.exit(f"Create the {role!r} role first (see ADR 0001): {exc}", 2)
    connection.close()
    return role


@pytest.fixture(scope="session")
def django_db_setup(
    _runtime_role: str, django_db_setup: None, django_db_blocker: Any
) -> Iterator[None]:
    if not POSTGRES:
        yield
        return
    options = connection.settings_dict["OPTIONS"]
    flush = type(connection.ops).execute_sql_flush

    def flush_as_owner(ops: Any, sql_list: list[str]) -> None:
        # Flushing between transactional tests truncates every table, which only
        # the owner may do; the runtime role never has TRUNCATE.
        with ops.connection.cursor() as cursor:
            cursor.execute("RESET ROLE")
        try:
            flush(ops, sql_list)
        finally:
            with ops.connection.cursor() as cursor:
                cursor.execute(f"SET ROLE {ops.quote_name(_runtime_role)}")

    setattr(type(connection.ops), "execute_sql_flush", flush_as_owner)  # noqa: B010
    options["assume_role"] = _runtime_role
    with django_db_blocker.unblock():
        for conn in connections.all():
            conn.close()
    yield
    options.pop("assume_role", None)
    setattr(type(connection.ops), "execute_sql_flush", flush)  # noqa: B010
    with django_db_blocker.unblock():
        for conn in connections.all():
            conn.close()


@contextmanager
def as_schema_owner() -> Iterator[None]:
    """Run as the login role (the schema owner, not the runtime role), then undo it all.

    Everything inside, the role switch included, is rolled back to a savepoint.
    """
    sid = transaction.savepoint()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SET LOCAL ROLE NONE")
        yield
    finally:
        transaction.savepoint_rollback(sid)


@pytest.fixture(autouse=True)
def _platform_scope_for_test_code() -> Iterator[None]:
    """Fixtures and assertions look across tenants; requests still start unscoped."""
    with rls.platform_scope():
        yield


@pytest.fixture(autouse=True)
def _isolate_cache() -> Iterator[None]:
    """Throttle counters live in the cache; never let them leak between tests."""
    cache.clear()
    yield
    cache.clear()


def make_user(email: str, role: str, organization: Organization | None, **extra: object) -> User:
    if role == Role.SUPER_ADMIN:
        return User.objects.create_superuser(email, PASSWORD, **extra)
    return User.objects.create_user(email, PASSWORD, role=role, organization=organization, **extra)


def make_invitation(organization: Organization, invited_by: User, email: str) -> Invitation:
    return Invitation.objects.create(
        organization=organization,
        email=email,
        role=Role.MEMBER,
        token_hash=hash_invitation_token(f"token-for-{email}"),
        invited_by=invited_by,
        expires_at=timezone.now() + timedelta(days=1),
    )


@dataclass
class World:
    """Two fully populated tenants plus a platform operator."""

    super_admin: User
    org_a: Organization
    admin_a: User
    member_a: User
    inactive_a: User
    invitation_a: Invitation
    audit_a: AuditLog
    sso_a: OidcProvider
    api_key_a: ApiKey
    org_b: Organization
    admin_b: User
    member_b: User
    inactive_b: User
    invitation_b: Invitation
    audit_b: AuditLog
    sso_b: OidcProvider
    api_key_b: ApiKey


@pytest.fixture
def world(db: None) -> World:
    super_admin = make_user("root@platform.test", Role.SUPER_ADMIN, None)
    tenants = {}
    for key, name in (("a", "Acme Corp"), ("b", "Globex Inc")):
        org = Organization.objects.create(name=name, slug=name.split()[0].lower())
        admin = make_user(f"admin@{key}.test", Role.ORG_ADMIN, org)
        member = make_user(f"member@{key}.test", Role.MEMBER, org)
        inactive = make_user(f"former@{key}.test", Role.MEMBER, org, is_active=False)
        invitation = make_invitation(org, admin, f"invitee@{key}.test")
        audit = record(AuditAction.USER_ROLE_CHANGED, actor=admin, organization=org, target=member)
        sso = OidcProvider.objects.create(
            organization=org,
            issuer=f"https://idp.{key}.test/realms/{key}",
            client_id=f"platform-{key}",
            client_secret_encrypted=crypto.encrypt(f"secret-{key}"),
        )
        api_key = ApiKey.objects.create(
            organization=org,
            name=f"SIEM export {key}",
            prefix=f"{key}0000000000{key}",
            secret_hash=hash_secret(f"secret-{key}"),
            scopes=["audit:read"],
            created_by=admin,
            expires_at=timezone.now() + timedelta(days=30),
        )
        tenants[key] = (org, admin, member, inactive, invitation, audit, sso, api_key)
    return World(super_admin, *tenants["a"], *tenants["b"])


ClientFactory = Callable[[User], APIClient]


def bearer(user: User) -> str:
    """An access token of a fresh, real session (refresh-token family)."""
    return str(sessions.start(user).access_token)


@pytest.fixture
def client_for() -> ClientFactory:
    """An API client authenticated with a real JWT (exercises our auth class)."""

    def _make(user: User) -> APIClient:
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {bearer(user)}")
        return client

    return _make


@pytest.fixture
def api_client() -> APIClient:
    return APIClient()


def forge_token(payload: dict[str, Any], key: str, algorithm: str = "HS256") -> str:
    return jwt.encode(payload, key, algorithm=algorithm)


def token_claims(user: User, **overrides: Any) -> dict[str, Any]:
    """Claims that would be accepted, so a test can break exactly one of them."""
    now = timezone.now()
    saved = User.objects.filter(pk=user.pk).exists()
    family = str(sessions.start(user)[FAMILY_CLAIM]) if saved else str(uuid.uuid4())
    return {
        "token_type": "access",
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "iat": int(now.timestamp()),
        "jti": "forged",
        "user_id": str(user.pk),
        "ver": user.token_version,
        "fam": family,
        "aud": settings.SIMPLE_JWT["AUDIENCE"],
        "iss": settings.SIMPLE_JWT["ISSUER"],
        **overrides,
    }
