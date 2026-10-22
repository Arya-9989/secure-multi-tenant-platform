"""Vertical privilege escalation and mass-assignment attempts."""

from __future__ import annotations

from typing import Any

import pytest
from django.conf import settings
from django.urls import reverse

from apps.accounts.models import User
from apps.accounts.roles import Role
from tests.conftest import ClientFactory, World, bearer, forge_token, token_claims

pytestmark = pytest.mark.django_db


def _reload(user: User) -> User:
    return User.objects.get(pk=user.pk)


@pytest.mark.parametrize(
    "payload",
    [
        {"role": "SUPER_ADMIN"},
        {"organization": "<org_b>"},
        {"is_staff": True},
        {"is_superuser": True},
        {"is_active": True},
        {"email": "takeover@a.test"},
        {"token_version": 0},
        {"role": "ORG_ADMIN", "organization": "<org_b>"},
    ],
    ids="+".join,
)
def test_org_admin_cannot_mass_assign_privileged_fields(
    world: World, client_for: ClientFactory, payload: dict[str, Any]
) -> None:
    payload = {k: str(world.org_b.pk) if v == "<org_b>" else v for k, v in payload.items()}
    before = User.objects.filter(pk=world.member_a.pk).values().get()
    response = client_for(world.admin_a).patch(
        reverse("user-detail", args=[world.member_a.pk]), payload
    )
    assert response.status_code == 400, response.content
    assert User.objects.filter(pk=world.member_a.pk).values().get() == before


def test_org_admin_cannot_make_themselves_super_admin(
    world: World, client_for: ClientFactory
) -> None:
    response = client_for(world.admin_a).patch(
        reverse("user-detail", args=[world.admin_a.pk]), {"role": "SUPER_ADMIN"}
    )
    assert response.status_code == 400
    assert _reload(world.admin_a).role == Role.ORG_ADMIN


@pytest.mark.parametrize(
    ("route", "body"),
    [("user-detail", {"role": "MEMBER"}), ("user-deactivate", {})],
)
def test_admins_cannot_modify_their_own_account(
    world: World, client_for: ClientFactory, route: str, body: dict[str, Any]
) -> None:
    method = "patch" if route == "user-detail" else "post"
    response = getattr(client_for(world.admin_a), method)(
        reverse(route, args=[world.admin_a.pk]), body
    )
    assert response.status_code == 403
    admin = _reload(world.admin_a)
    assert admin.role == Role.ORG_ADMIN
    assert admin.is_active


def test_member_cannot_promote_themselves(world: World, client_for: ClientFactory) -> None:
    response = client_for(world.member_a).patch(
        reverse("user-detail", args=[world.member_a.pk]), {"role": "ORG_ADMIN"}
    )
    assert response.status_code == 403
    assert _reload(world.member_a).role == Role.MEMBER


@pytest.mark.parametrize(
    "payload",
    [
        {"role": "ORG_ADMIN"},
        {"organization": "<org_b>"},
        {"is_staff": True},
        {"email": "x@y.test"},
        {"is_active": False},
    ],
    ids="+".join,
)
def test_profile_endpoint_rejects_privileged_fields(
    world: World, client_for: ClientFactory, payload: dict[str, Any]
) -> None:
    payload = {k: str(world.org_b.pk) if v == "<org_b>" else v for k, v in payload.items()}
    response = client_for(world.member_a).patch(reverse("auth-me"), payload)
    assert response.status_code == 400
    member = _reload(world.member_a)
    assert (member.role, member.organization_id, member.is_staff) == (
        Role.MEMBER,
        world.org_a.pk,
        False,
    )


def test_cannot_invite_a_super_admin(world: World, client_for: ClientFactory) -> None:
    for actor in (world.admin_a, world.super_admin):
        response = client_for(actor).post(
            reverse("invitation-list"),
            {"email": "boss@a.test", "role": "SUPER_ADMIN", "organization": str(world.org_a.pk)},
        )
        assert response.status_code == 400
        assert "role" in response.json()


def test_org_admin_cannot_see_or_touch_super_admins(
    world: World, client_for: ClientFactory
) -> None:
    client = client_for(world.admin_a)
    assert client.get(reverse("user-detail", args=[world.super_admin.pk])).status_code == 404
    response = client.post(reverse("user-deactivate", args=[world.super_admin.pk]))
    assert response.status_code == 404
    assert _reload(world.super_admin).is_active


def test_super_admin_accounts_are_not_manageable_over_http(
    world: World, client_for: ClientFactory
) -> None:
    other_root = User.objects.create_superuser("root2@platform.test", "Irrelevant-Pass-123")
    client = client_for(world.super_admin)
    response = client.patch(reverse("user-detail", args=[other_root.pk]), {"role": "MEMBER"})
    assert response.status_code == 403
    response = client.post(reverse("user-deactivate", args=[other_root.pk]))
    assert response.status_code == 403
    assert _reload(other_root).is_active


def test_last_active_org_admin_cannot_be_removed(world: World, client_for: ClientFactory) -> None:
    client = client_for(world.super_admin)
    demote = client.patch(reverse("user-detail", args=[world.admin_a.pk]), {"role": "MEMBER"})
    deactivate = client.post(reverse("user-deactivate", args=[world.admin_a.pk]))
    assert demote.status_code == deactivate.status_code == 400
    admin = _reload(world.admin_a)
    assert admin.role == Role.ORG_ADMIN
    assert admin.is_active


def test_organization_create_rejects_unknown_fields(
    world: World, client_for: ClientFactory
) -> None:
    response = client_for(world.super_admin).post(
        reverse("organization-list"),
        {"name": "Initech", "id": "00000000-0000-0000-0000-000000000001", "member_count": 9},
    )
    assert response.status_code == 400
    assert set(response.json()) == {"id", "member_count"}


# ---------------------------------------------------------------- token forgery
@pytest.mark.parametrize(
    "token_factory",
    [
        pytest.param(
            lambda w: forge_token(
                token_claims(w.super_admin), "an-attacker-chosen-key-that-is-long-enough"
            ),
            id="wrong-key",
        ),
        pytest.param(
            lambda w: forge_token(token_claims(w.super_admin), "", algorithm="none"), id="alg-none"
        ),
        pytest.param(
            lambda w: forge_token(
                token_claims(w.member_a, aud="other-service"), settings.SECRET_KEY
            ),
            id="wrong-audience",
        ),
        pytest.param(
            lambda w: forge_token(token_claims(w.member_a, iss="evil"), settings.SECRET_KEY),
            id="wrong-issuer",
        ),
        pytest.param(
            lambda w: forge_token(token_claims(w.member_a, exp=1), settings.SECRET_KEY),
            id="expired",
        ),
        pytest.param(
            lambda w: forge_token(token_claims(w.member_a, ver=99), settings.SECRET_KEY),
            id="stale-version",
        ),
        pytest.param(
            lambda w: forge_token(
                token_claims(w.member_a, token_type="refresh"), settings.SECRET_KEY
            ),
            id="refresh-as-access",
        ),
        pytest.param(
            lambda w: bearer(w.member_a)[:-4] + "AAAA",
            id="tampered-signature",
        ),
    ],
)
def test_forged_or_invalid_tokens_are_rejected(
    world: World, api_client: Any, token_factory: Any
) -> None:
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token_factory(world)}")
    assert api_client.get(reverse("user-list")).status_code == 401


def test_role_claims_in_token_are_ignored(world: World, api_client: Any) -> None:
    """Authorization reads role/tenant from the database, never from the token."""
    token = forge_token(
        token_claims(world.member_a, role="SUPER_ADMIN", organization=str(world.org_b.pk)),
        settings.SECRET_KEY,
    )
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    assert api_client.get(reverse("auditlog-list")).status_code == 403
    response = api_client.get(reverse("user-list"))
    assert {row["organization"] for row in response.json()["results"]} == {str(world.org_a.pk)}
