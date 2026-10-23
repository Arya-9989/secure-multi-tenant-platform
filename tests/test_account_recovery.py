"""Functions a production user needs: resetting a forgotten password, seeing and
ending their own sessions, and an admin signing a member out everywhere."""

from __future__ import annotations

import re
from typing import Any

import pytest
from django.core import mail
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from apps.accounts.models import RefreshTokenFamily, SessionEndReason
from apps.auditlogs.models import AuditAction, AuditLog
from apps.common.throttling import ClientScopedRateThrottle
from apps.tasks import worker
from tests.conftest import PASSWORD, ClientFactory, World

pytestmark = pytest.mark.django_db

RESET = "/api/v1/auth/password/reset/"
CONFIRM = "/api/v1/auth/password/reset/confirm/"
NEW = "A-Fresh-Passphrase-2026"


@pytest.fixture(autouse=True)
def _no_per_ip_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """The per-IP credential limit is tested in test_auth.py."""
    monkeypatch.setattr(ClientScopedRateThrottle, "allow_request", lambda *a: True)


def login(email: str = "member@a.test", password: str = PASSWORD) -> Any:
    return APIClient().post(reverse("auth-login"), {"email": email, "password": password})


def link_parts() -> dict[str, str]:
    (message,) = mail.outbox
    match = re.search(r"uid=([\w-]+)&token=([\w-]+)", str(message.body))
    assert match, message.body
    return {"uid": match[1], "token": match[2]}


# ---------------------------------------------------------------- password reset
def test_a_forgotten_password_is_reset_by_email(world: World) -> None:
    sessions = [login().json(), login().json()]
    response = APIClient().post(RESET, {"email": "Member@A.test"})
    assert response.status_code == 202
    assert mail.outbox == [], "looked up and sent by the worker"
    worker.drain()
    assert mail.outbox[0].to == ["member@a.test"]
    parts = link_parts()

    assert APIClient().post(CONFIRM, {**parts, "new_password": NEW}).status_code == 204
    assert login(password=PASSWORD).status_code == 401
    assert login(password=NEW).status_code == 200
    for tokens in sessions:  # every session ended
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        assert client.get("/api/v1/auth/me/").status_code == 401
    assert {
        s.revoked_reason for s in RefreshTokenFamily.objects.filter(revoked_at__isnull=False)
    } == {SessionEndReason.PASSWORD_RESET}
    actions = set(AuditLog.objects.values_list("action", flat=True))
    assert {AuditAction.PASSWORD_RESET_REQUESTED, AuditAction.PASSWORD_RESET} <= actions
    # The link works once.
    again = APIClient().post(CONFIRM, {**parts, "new_password": "Yet-Another-Phrase-3"})
    assert again.status_code == 400


def test_unknown_and_known_addresses_get_the_same_answer(world: World) -> None:
    known = APIClient().post(RESET, {"email": "member@a.test"})
    unknown = APIClient().post(RESET, {"email": "nobody@nowhere.test"})
    inactive = APIClient().post(RESET, {"email": "former@a.test"})
    assert known.status_code == unknown.status_code == inactive.status_code == 202
    assert known.json() == unknown.json() == inactive.json()
    worker.drain()
    assert [m.to for m in mail.outbox] == [["member@a.test"]]


@override_settings(PASSWORD_RESET_MAX_PER_HOUR=2)
def test_reset_links_to_one_address_are_rate_limited(world: World) -> None:
    for _ in range(4):
        assert APIClient().post(RESET, {"email": "member@a.test"}).status_code == 202
        worker.drain()
    assert len(mail.outbox) == 2


@pytest.mark.parametrize(
    "tamper",
    [
        {"token": "abc-123"},
        {"uid": "bm90LWEtdXVpZA"},
        {"uid": "!!!"},
    ],
    ids=["wrong-token", "unknown-user", "garbage-uid"],
)
def test_bad_links_fail_the_same_way(world: World, tamper: dict[str, str]) -> None:
    APIClient().post(RESET, {"email": "member@a.test"})
    worker.drain()
    response = APIClient().post(CONFIRM, {**link_parts(), **tamper, "new_password": NEW})
    assert response.status_code == 400
    assert response.json() == {"token": ["This reset link is invalid or has expired."]}
    assert login().status_code == 200, "the password is unchanged"


def test_a_link_for_one_user_cannot_reset_another(world: World) -> None:
    APIClient().post(RESET, {"email": "member@a.test"})
    worker.drain()
    parts = link_parts()
    mail.outbox.clear()
    APIClient().post(RESET, {"email": "member@b.test"})
    worker.drain()
    other = link_parts()
    response = APIClient().post(
        CONFIRM, {"uid": other["uid"], "token": parts["token"], "new_password": NEW}
    )
    assert response.status_code == 400


def test_signing_out_everywhere_kills_pending_reset_links(
    world: World, client_for: ClientFactory
) -> None:
    APIClient().post(RESET, {"email": "member@a.test"})
    worker.drain()
    client_for(world.member_a).post("/api/v1/auth/logout-all/")
    assert APIClient().post(CONFIRM, {**link_parts(), "new_password": NEW}).status_code == 400


def test_a_reset_keeps_the_password_rules(world: World) -> None:
    APIClient().post(RESET, {"email": "member@a.test"})
    worker.drain()
    response = APIClient().post(CONFIRM, {**link_parts(), "new_password": "short"})
    assert response.status_code == 400
    assert "password" in response.json()


@override_settings(PASSWORD_RESET_TIMEOUT=1)
def test_links_expire(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    import datetime as dt  # noqa: PLC0415

    from apps.accounts import password_reset  # noqa: PLC0415

    APIClient().post(RESET, {"email": "member@a.test"})
    worker.drain()
    later = dt.datetime.now() + dt.timedelta(seconds=30)
    monkeypatch.setattr(password_reset.tokens, "_now", lambda: later)
    assert APIClient().post(CONFIRM, {**link_parts(), "new_password": NEW}).status_code == 400


# ---------------------------------------------------------------- your sessions
def test_you_see_your_live_sessions_and_which_one_is_this(world: World) -> None:
    first = login().json()
    login()
    login("admin@a.test")  # someone else's
    client = APIClient(HTTP_USER_AGENT="laptop/1.0")
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {first['access']}")
    sessions = client.get("/api/v1/auth/sessions/").json()
    assert len(sessions) == 2
    assert sum(s["current"] for s in sessions) == 1
    assert {"id", "created_at", "ip_address", "user_agent", "expires_at"} <= set(sessions[0])


def test_ending_one_of_your_sessions(world: World) -> None:
    phone, laptop = login().json(), login().json()
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {laptop['access']}")
    sessions = client.get("/api/v1/auth/sessions/").json()
    phone_id = next(s["id"] for s in sessions if not s["current"])
    assert client.post(f"/api/v1/auth/sessions/{phone_id}/revoke/").status_code == 204
    gone = APIClient()
    gone.credentials(HTTP_AUTHORIZATION=f"Bearer {phone['access']}")
    assert gone.get("/api/v1/auth/me/").status_code == 401
    assert client.get("/api/v1/auth/me/").status_code == 200
    assert len(client.get("/api/v1/auth/sessions/").json()) == 1
    assert AuditLog.objects.filter(action=AuditAction.SESSION_REVOKED).count() == 1
    assert client.post(f"/api/v1/auth/sessions/{phone_id}/revoke/").status_code == 404


@pytest.mark.parametrize(
    "owner", ["admin@a.test", "member@b.test"], ids=["same-tenant", "other-tenant"]
)
def test_another_users_session_is_not_found(world: World, owner: str) -> None:
    victim = login(owner).json()
    victim_session = RefreshTokenFamily.objects.get(user__email=owner)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {login().json()['access']}")
    foreign = client.post(f"/api/v1/auth/sessions/{victim_session.pk}/revoke/")
    missing = client.post("/api/v1/auth/sessions/00000000-0000-0000-0000-000000000000/revoke/")
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()
    still = APIClient()
    still.credentials(HTTP_AUTHORIZATION=f"Bearer {victim['access']}")
    assert still.get("/api/v1/auth/me/").status_code == 200


# ---------------------------------------------------------------- admin: sign out everywhere
def test_an_admin_signs_a_member_out_everywhere(world: World, client_for: ClientFactory) -> None:
    sessions = [login().json(), login().json()]
    url = reverse("user-revoke-sessions", args=[world.member_a.pk])
    assert client_for(world.admin_a).post(url).status_code == 204
    for tokens in sessions:
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        assert client.get("/api/v1/auth/me/").status_code == 401
    world.member_a.refresh_from_db()
    assert world.member_a.is_active, "signed out, not deactivated"
    assert login().status_code == 200
    event = AuditLog.objects.get(action=AuditAction.USER_SESSIONS_REVOKED)
    assert (event.actor, event.target_id) == (world.admin_a, str(world.member_a.pk))


def test_admins_cannot_sign_themselves_out_this_way(
    world: World, client_for: ClientFactory
) -> None:
    url = reverse("user-revoke-sessions", args=[world.admin_a.pk])
    assert client_for(world.admin_a).post(url).status_code == 403
