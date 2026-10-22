from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import jwt
import pytest
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.authentication import TenantRefreshToken
from apps.accounts.models import Invitation, User, hash_invitation_token
from apps.accounts.roles import Role
from apps.auditlogs.models import AuditAction, AuditLog
from apps.auditlogs.services import record
from apps.organizations.models import Organization

PASSWORD = "Correct-Horse-Battery-9"


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
    org_b: Organization
    admin_b: User
    member_b: User
    inactive_b: User
    invitation_b: Invitation
    audit_b: AuditLog


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
        tenants[key] = (org, admin, member, inactive, invitation, audit)
    return World(super_admin, *tenants["a"], *tenants["b"])


ClientFactory = Callable[[User], APIClient]


def bearer(user: User) -> str:
    return str(TenantRefreshToken.for_user(user).access_token)


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
    now = timezone.now()
    return {
        "token_type": "access",
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "iat": int(now.timestamp()),
        "jti": "forged",
        "user_id": str(user.pk),
        "ver": user.token_version,
        "aud": settings.SIMPLE_JWT["AUDIENCE"],
        "iss": settings.SIMPLE_JWT["ISSUER"],
        **overrides,
    }
