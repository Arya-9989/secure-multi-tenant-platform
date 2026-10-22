from __future__ import annotations

from typing import Any, cast

import pytest
from django.conf import settings
from django.test import override_settings
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken

from apps.accounts.models import User
from apps.auditlogs.models import AuditAction, AuditLog
from tests.conftest import PASSWORD, World, forge_token, token_claims

pytestmark = pytest.mark.django_db

LOGIN = "/api/v1/auth/login/"
REFRESH = "/api/v1/auth/refresh/"


def login(client: APIClient, email: str, password: str = PASSWORD, **extra: Any) -> Any:
    return client.post(LOGIN, {"email": email, "password": password}, **extra)


def authed(access: str) -> APIClient:
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
    return client


def test_login_returns_token_pair_and_is_audited(world: World, api_client: APIClient) -> None:
    response = login(
        api_client,
        "Member@A.test",  # emails are case-insensitive
        HTTP_X_REQUEST_ID="req-login-0001",
        HTTP_USER_AGENT="pytest-agent",
    )
    assert response.status_code == 200
    assert set(response.json()) == {"access", "refresh"}

    event = AuditLog.objects.get(action=AuditAction.LOGIN_SUCCEEDED)
    assert event.actor == world.member_a
    assert event.organization == world.org_a
    assert event.request_id == "req-login-0001"
    assert event.ip_address == "127.0.0.1"
    assert event.user_agent == "pytest-agent"


def test_access_tokens_are_short_lived(world: World, api_client: APIClient) -> None:
    access = AccessToken(login(api_client, "member@a.test").json()["access"])
    assert access["exp"] - access["iat"] == 300
    assert settings.SIMPLE_JWT["ROTATE_REFRESH_TOKENS"] is True


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("member@a.test", "wrong-password"),
        ("nobody@nowhere.test", PASSWORD),
        ("former@a.test", PASSWORD),  # deactivated user
    ],
    ids=["wrong-password", "unknown-email", "inactive-user"],
)
def test_failed_logins_are_generic_and_audited(
    world: World, api_client: APIClient, email: str, password: str
) -> None:
    response = login(api_client, email, password)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."
    event = AuditLog.objects.get(action=AuditAction.LOGIN_FAILED)
    assert event.metadata == {"email": email}
    assert event.actor is None
    # Known accounts are attributed to their tenant so its admins can see attacks.
    assert event.organization == (None if email.startswith("nobody") else world.org_a)


def test_users_of_a_deactivated_organization_cannot_log_in(
    world: World, api_client: APIClient
) -> None:
    world.org_a.is_active = False
    world.org_a.save()
    assert login(api_client, "admin@a.test").status_code == 401
    assert login(api_client, "admin@b.test").status_code == 200


def test_refresh_rotates_and_blacklists_the_old_token(world: World, api_client: APIClient) -> None:
    first = login(api_client, "member@a.test").json()
    rotated = api_client.post(REFRESH, {"refresh": first["refresh"]})
    assert rotated.status_code == 200
    assert set(rotated.json()) == {"access", "refresh"}
    assert rotated.json()["refresh"] != first["refresh"]

    replay = api_client.post(REFRESH, {"refresh": first["refresh"]})
    assert replay.status_code == 401
    assert api_client.post(REFRESH, {"refresh": rotated.json()["refresh"]}).status_code == 200


def test_access_token_cannot_be_used_as_refresh(world: World, api_client: APIClient) -> None:
    tokens = login(api_client, "member@a.test").json()
    assert api_client.post(REFRESH, {"refresh": tokens["access"]}).status_code == 401


def test_logout_blacklists_refresh_token(world: World, api_client: APIClient) -> None:
    tokens = login(api_client, "member@a.test").json()
    client = authed(tokens["access"])
    assert client.post("/api/v1/auth/logout/", {"refresh": tokens["refresh"]}).status_code == 204
    assert api_client.post(REFRESH, {"refresh": tokens["refresh"]}).status_code == 401
    assert client.post("/api/v1/auth/logout/", {"refresh": tokens["refresh"]}).status_code == 400
    assert AuditLog.objects.filter(action=AuditAction.LOGOUT, actor=world.member_a).exists()


def test_cannot_log_out_someone_else(world: World, api_client: APIClient) -> None:
    victim = login(api_client, "member@b.test").json()
    attacker = login(api_client, "admin@a.test").json()
    response = authed(attacker["access"]).post(
        "/api/v1/auth/logout/", {"refresh": victim["refresh"]}
    )
    assert response.status_code == 400
    assert api_client.post(REFRESH, {"refresh": victim["refresh"]}).status_code == 200


def test_logout_rejects_garbage(world: World, api_client: APIClient) -> None:
    tokens = login(api_client, "member@a.test").json()
    response = authed(tokens["access"]).post("/api/v1/auth/logout/", {"refresh": "not-a-jwt"})
    assert response.status_code == 400


def test_logout_all_revokes_access_and_refresh_tokens_immediately(
    world: World, api_client: APIClient
) -> None:
    session_1 = login(api_client, "member@a.test").json()
    session_2 = login(api_client, "member@a.test").json()
    assert authed(session_1["access"]).post("/api/v1/auth/logout-all/").status_code == 204

    for session in (session_1, session_2):
        assert authed(session["access"]).get("/api/v1/auth/me/").status_code == 401
        assert api_client.post(REFRESH, {"refresh": session["refresh"]}).status_code == 401
    # A fresh login works again.
    fresh = login(api_client, "member@a.test").json()
    assert authed(fresh["access"]).get("/api/v1/auth/me/").status_code == 200


def test_deactivation_takes_effect_on_the_next_request(world: World, api_client: APIClient) -> None:
    tokens = login(api_client, "member@a.test").json()
    member = authed(tokens["access"])
    assert member.get("/api/v1/auth/me/").status_code == 200

    admin = authed(login(api_client, "admin@a.test").json()["access"])
    assert admin.post(f"/api/v1/users/{world.member_a.pk}/deactivate/").status_code == 200

    assert member.get("/api/v1/auth/me/").status_code == 401
    assert api_client.post(REFRESH, {"refresh": tokens["refresh"]}).status_code == 401
    assert login(api_client, "member@a.test").status_code == 401


def test_deactivating_an_organization_cuts_off_live_sessions(
    world: World, api_client: APIClient
) -> None:
    tokens = login(api_client, "member@a.test").json()
    world.org_a.is_active = False
    world.org_a.save()
    assert authed(tokens["access"]).get("/api/v1/auth/me/").status_code == 401
    assert api_client.post(REFRESH, {"refresh": tokens["refresh"]}).status_code == 401


def _auth_limit() -> int:
    rates = cast(dict[str, Any], settings.REST_FRAMEWORK)["DEFAULT_THROTTLE_RATES"]
    return int(rates["auth"].split("/")[0])


def test_login_is_throttled(world: World, api_client: APIClient) -> None:
    limit = _auth_limit()
    for _ in range(limit):
        assert login(api_client, "member@a.test", "wrong").status_code == 401
    response = login(api_client, "member@a.test")  # even correct credentials
    assert response.status_code == 429
    assert "Retry-After" in response.headers


def test_login_throttle_ignores_a_spoofed_forwarded_for(
    world: World, api_client: APIClient
) -> None:
    """Without a trusted proxy, X-Forwarded-For is attacker-controlled.

    A fresh value per request must not buy a fresh throttle budget.
    """
    limit = _auth_limit()
    for attempt in range(limit):
        spoofed = {"HTTP_X_FORWARDED_FOR": f"203.0.113.{attempt}"}
        assert login(api_client, "member@a.test", "wrong", **spoofed).status_code == 401
    response = login(api_client, "member@a.test", HTTP_X_FORWARDED_FOR="198.51.100.250")
    assert response.status_code == 429


@override_settings(NUM_PROXIES=1)
def test_behind_a_trusted_proxy_the_throttle_keys_on_the_address_it_appended(
    world: World, api_client: APIClient
) -> None:
    limit = _auth_limit()
    for attempt in range(limit):
        # The client controls everything left of the address our proxy appended.
        chain = {"HTTP_X_FORWARDED_FOR": f"203.0.113.{attempt}, 198.51.100.7"}
        assert login(api_client, "member@a.test", "wrong", **chain).status_code == 401
    attacker = {"HTTP_X_FORWARDED_FOR": "203.0.113.99, 198.51.100.7"}
    assert login(api_client, "member@a.test", **attacker).status_code == 429
    # A different client behind the same proxy has its own budget.
    other = {"HTTP_X_FORWARDED_FOR": "198.51.100.8"}
    assert login(api_client, "member@a.test", **other).status_code == 200
    assert AuditLog.objects.filter(ip_address="198.51.100.8").exists()


# ---------------------------------------------------------------- profile & password
def test_me_returns_and_updates_own_profile(world: World, api_client: APIClient) -> None:
    client = authed(login(api_client, "member@a.test").json()["access"])
    me = client.get("/api/v1/auth/me/").json()
    assert me["email"] == "member@a.test"
    assert me["role"] == "MEMBER"
    assert me["organization"] == str(world.org_a.pk)

    response = client.patch("/api/v1/auth/me/", {"full_name": "Bob Builder"})
    assert response.status_code == 200
    assert response.json()["full_name"] == "Bob Builder"
    assert AuditLog.objects.filter(action=AuditAction.USER_PROFILE_UPDATED).count() == 1
    client.patch("/api/v1/auth/me/", {"full_name": "Bob Builder"})  # no-op: not audited again
    assert AuditLog.objects.filter(action=AuditAction.USER_PROFILE_UPDATED).count() == 1


def test_password_change_validates_and_revokes_sessions(
    world: World, api_client: APIClient
) -> None:
    tokens = login(api_client, "member@a.test").json()
    client = authed(tokens["access"])
    url = "/api/v1/auth/password/change/"

    wrong = client.post(url, {"current_password": "nope", "new_password": "An0ther-Good-One"})
    assert wrong.status_code == 400
    assert "current_password" in wrong.json()

    for weak in ("short1!", "password1234", "12345678901234", "member@a.test"):
        response = client.post(url, {"current_password": PASSWORD, "new_password": weak})
        assert response.status_code == 400, weak
        assert "password" in response.json()

    response = client.post(url, {"current_password": PASSWORD, "new_password": "An0ther-Good-One"})
    assert response.status_code == 204
    assert client.get("/api/v1/auth/me/").status_code == 401
    assert api_client.post(REFRESH, {"refresh": tokens["refresh"]}).status_code == 401
    assert login(api_client, "member@a.test").status_code == 401
    assert login(api_client, "member@a.test", "An0ther-Good-One").status_code == 200
    assert AuditLog.objects.filter(action=AuditAction.PASSWORD_CHANGED).exists()


def test_token_for_deleted_or_malformed_user_is_rejected(world: World) -> None:
    ghost = User(email="ghost@a.test", role="MEMBER", organization=world.org_a)
    token = forge_token(token_claims(ghost), settings.SECRET_KEY)
    assert authed(token).get("/api/v1/auth/me/").status_code == 401
    token = forge_token(token_claims(world.member_a, user_id="not-a-uuid"), settings.SECRET_KEY)
    assert authed(token).get("/api/v1/auth/me/").status_code == 401
    claims = token_claims(world.member_a)
    del claims["user_id"]
    assert (
        authed(forge_token(claims, settings.SECRET_KEY)).get("/api/v1/auth/me/").status_code == 401
    )
