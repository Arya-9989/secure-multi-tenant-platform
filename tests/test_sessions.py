"""Sessions as refresh-token families, with reuse detection (ADR 0002).

A rotated refresh token that comes back is either the client or a thief
replaying it. Either way the whole session is revoked, its access tokens stop
working at once, and the tenant's administrators can see the event.
"""

from __future__ import annotations

import io
import threading
from datetime import timedelta
from typing import Any

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connections
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.utils import datetime_to_epoch

from apps.accounts.models import RefreshTokenFamily, SessionEndReason
from apps.auditlogs.models import AuditAction, AuditLog
from tests.conftest import (
    PASSWORD,
    POSTGRES,
    ClientFactory,
    World,
    forge_token,
    token_claims,
)

pytestmark = pytest.mark.django_db

LOGIN = "/api/v1/auth/login/"
REFRESH = "/api/v1/auth/refresh/"
ME = "/api/v1/auth/me/"


def login(email: str = "member@a.test") -> dict[str, str]:
    response = APIClient().post(LOGIN, {"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.content
    tokens: dict[str, str] = response.json()
    return tokens


def refresh(token: str) -> Any:
    return APIClient().post(REFRESH, {"refresh": token})


def me(access: str) -> int:
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
    return client.get(ME).status_code


def family_of(token: str) -> RefreshTokenFamily:
    return RefreshTokenFamily.objects.get(pk=RefreshToken(token)["fam"])  # type: ignore[arg-type]


def reuse_events() -> list[AuditLog]:
    return list(AuditLog.objects.filter(action=AuditAction.REFRESH_TOKEN_REUSE_DETECTED))


# ---------------------------------------------------------------- the family
def test_a_login_starts_a_session_that_stores_no_token(world: World) -> None:
    tokens = login()
    claims = RefreshToken(tokens["refresh"])  # type: ignore[arg-type]
    session = family_of(tokens["refresh"])
    assert session.user == world.member_a
    assert session.organization == world.org_a
    assert (claims["gen"], session.generation) == (0, 0)
    assert claims["jti"] == session.current_jti
    assert AccessToken(tokens["access"])["fam"] == str(session.pk)  # type: ignore[arg-type]
    stored = RefreshTokenFamily.objects.filter(pk=session.pk).values().get()
    assert tokens["refresh"] not in str(stored)
    assert session.ip_address == "127.0.0.1"


def test_rotation_moves_the_family_forward(world: World) -> None:
    first = login()
    second = refresh(first["refresh"]).json()
    third = refresh(second["refresh"]).json()
    session = family_of(third["refresh"])
    assert session.generation == 2
    assert RefreshToken(third["refresh"])["gen"] == 2
    assert session.current_jti == RefreshToken(third["refresh"])["jti"]
    assert session.last_refreshed_at is not None
    assert me(third["access"]) == 200
    assert RefreshTokenFamily.objects.count() == 1, "rotation never starts a new session"


# ---------------------------------------------------------------- reuse
def test_replaying_a_rotated_token_revokes_the_whole_session(world: World) -> None:
    stolen = login()
    newest = refresh(refresh(stolen["refresh"]).json()["refresh"]).json()
    other_session = login()

    replay = refresh(stolen["refresh"])
    assert replay.status_code == 401

    session = family_of(stolen["refresh"])
    assert session.revoked_reason == SessionEndReason.REUSE_DETECTED
    assert session.revoked_at is not None
    # The legitimate holder's newest tokens are dead too: both copies stop working.
    assert refresh(newest["refresh"]).status_code == 401
    assert me(newest["access"]) == 401
    # Only that session: the user's other sessions carry on.
    assert me(other_session["access"]) == 200
    assert refresh(other_session["refresh"]).status_code == 200

    (event,) = reuse_events()
    assert event.organization == world.org_a
    assert event.actor is None, "who replayed it is unknown"
    assert (event.target_type, event.target_id) == ("accounts.user", str(world.member_a.pk))
    assert event.metadata == {
        "session": str(session.pk),
        "presented_generation": 0,
        "current_generation": 2,
    }


def test_a_replay_answers_exactly_like_any_invalid_token(world: World) -> None:
    tokens = login()
    refresh(tokens["refresh"])
    replay = refresh(tokens["refresh"])
    tampered = refresh(tokens["refresh"][:-4] + "AAAA")
    assert replay.status_code == tampered.status_code == 401
    assert replay.json()["code"] == tampered.json()["code"] == "token_not_valid"
    assert refresh(tokens["refresh"]).json() == replay.json(), "after revocation, the same answer"


def test_repeated_replays_record_one_event(world: World) -> None:
    tokens = login()
    refresh(tokens["refresh"])
    for _ in range(3):
        assert refresh(tokens["refresh"]).status_code == 401
    assert len(reuse_events()) == 1


def test_the_reuse_event_is_visible_to_its_tenant_only(
    world: World, client_for: ClientFactory
) -> None:
    tokens = login()
    refresh(tokens["refresh"])
    refresh(tokens["refresh"])
    url = reverse("auditlog-list")
    action = {"action": AuditAction.REFRESH_TOKEN_REUSE_DETECTED}
    assert len(client_for(world.admin_a).get(url, action).json()["results"]) == 1
    assert client_for(world.admin_b).get(url, action).json()["results"] == []


def test_an_expired_session_is_invalid_but_not_reuse(world: World) -> None:
    tokens = login()
    RefreshTokenFamily.objects.filter(user=world.member_a).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )
    assert refresh(tokens["refresh"]).status_code == 401
    assert me(tokens["access"]) == 401
    assert reuse_events() == []


@override_settings(JWT_SESSION_MAX_AGE=timedelta(hours=2))
def test_no_refresh_token_outlives_its_session(world: World) -> None:
    tokens = login()
    session = family_of(tokens["refresh"])
    assert RefreshToken(tokens["refresh"])["exp"] <= datetime_to_epoch(session.expires_at)  # type: ignore[arg-type]
    assert session.expires_at <= timezone.now() + timedelta(hours=2)


# ---------------------------------------------------------------- forged session claims
@pytest.mark.parametrize(
    "claims",
    [
        pytest.param(lambda w: {"fam": None}, id="no-session"),
        pytest.param(lambda w: {"fam": "not-a-uuid"}, id="malformed-session"),
        pytest.param(lambda w: {"fam": "00000000-0000-0000-0000-000000000000"}, id="unknown"),
        pytest.param(
            lambda w: {"fam": token_claims(w.member_b)["fam"]}, id="another-users-session"
        ),
    ],
)
def test_access_tokens_must_name_a_live_session_of_their_user(world: World, claims: Any) -> None:
    from django.conf import settings  # noqa: PLC0415

    payload = token_claims(world.member_a, **claims(world))
    if payload["fam"] is None:
        del payload["fam"]
    assert me(forge_token(payload, settings.SECRET_KEY)) == 401


def test_a_refresh_token_without_a_session_is_rejected(world: World) -> None:
    from django.conf import settings  # noqa: PLC0415

    legacy = token_claims(world.member_a, token_type="refresh")
    del legacy["fam"]
    assert refresh(forge_token(legacy, settings.SECRET_KEY)).status_code == 401
    assert reuse_events() == []


# ---------------------------------------------------------------- ending sessions
@pytest.mark.parametrize(
    ("trigger", "reason"),
    [
        ("logout-all", SessionEndReason.LOGOUT_ALL),
        ("password", SessionEndReason.PASSWORD_CHANGED),
        ("deactivate", SessionEndReason.USER_DEACTIVATED),
        ("organization", SessionEndReason.ORGANIZATION_DEACTIVATED),
    ],
)
def test_every_session_of_the_user_ends_with_a_reason(
    world: World, client_for: ClientFactory, trigger: str, reason: SessionEndReason
) -> None:
    sessions = [login(), login()]
    own = APIClient()
    own.credentials(HTTP_AUTHORIZATION=f"Bearer {sessions[0]['access']}")
    match trigger:
        case "logout-all":
            assert own.post("/api/v1/auth/logout-all/").status_code == 204
        case "password":
            response = own.post(
                "/api/v1/auth/password/change/",
                {"current_password": PASSWORD, "new_password": "A-Brand-New-Passphrase-1"},
            )
            assert response.status_code == 204
        case "deactivate":
            url = reverse("user-deactivate", args=[world.member_a.pk])
            assert client_for(world.admin_a).post(url).status_code == 200
        case "organization":
            url = reverse("organization-detail", args=[world.org_a.pk])
            assert client_for(world.super_admin).patch(url, {"is_active": False}).status_code == 200
    ended = RefreshTokenFamily.objects.filter(user=world.member_a)
    assert {(s.revoked_reason, s.revoked_at is not None) for s in ended} == {(reason, True)}
    for tokens in sessions:
        assert me(tokens["access"]) == 401
        assert refresh(tokens["refresh"]).status_code == 401
    assert reuse_events() == []


def test_prune_sessions_deletes_only_long_ended_ones(world: World) -> None:
    live, ended, old_revoked, old_expired = (login() for _ in range(4))
    now = timezone.now()
    RefreshTokenFamily.objects.filter(pk=family_of(ended["refresh"]).pk).update(
        revoked_at=now, revoked_reason=SessionEndReason.LOGOUT
    )
    RefreshTokenFamily.objects.filter(pk=family_of(old_revoked["refresh"]).pk).update(
        revoked_at=now - timedelta(days=40), revoked_reason=SessionEndReason.LOGOUT
    )
    RefreshTokenFamily.objects.filter(pk=family_of(old_expired["refresh"]).pk).update(
        expires_at=now - timedelta(days=31)
    )
    out = io.StringIO()
    call_command("prune_sessions", "--days", "30", stdout=out)
    assert "Deleted 2 session(s)" in out.getvalue()
    remaining = set(RefreshTokenFamily.objects.values_list("pk", flat=True))
    assert remaining == {family_of(live["refresh"]).pk, family_of(ended["refresh"]).pk}
    with pytest.raises(CommandError, match="negative"):
        call_command("prune_sessions", "--days", "-1")


# ---------------------------------------------------------------- concurrency
def _race(tokens: list[str]) -> list[int]:
    """Send every refresh at the same instant, each on its own connection."""
    barrier = threading.Barrier(len(tokens))
    statuses: list[int] = []
    lock = threading.Lock()

    def send(token: str) -> None:
        try:
            barrier.wait(timeout=10)
            status = refresh(token).status_code
            with lock:
                statuses.append(status)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=send, args=(token,)) for token in tokens]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert len(statuses) == len(tokens), "a request did not finish"
    return statuses


@pytest.mark.skipif(not POSTGRES, reason="needs concurrent connections (PostgreSQL)")
@pytest.mark.django_db(transaction=True)
def test_concurrent_refreshes_with_one_token_have_exactly_one_winner(world: World) -> None:
    """Eight requests, one token. The compare-and-swap lets exactly one rotate the
    family; the rest present a token that is no longer current, which is reuse."""
    tokens = login()
    statuses = _race([tokens["refresh"]] * 8)
    assert sorted(statuses) == [200] + [401] * 7

    session = family_of(tokens["refresh"])
    assert session.generation == 1, "never forked: one rotation, one successor"
    assert session.revoked_reason == SessionEndReason.REUSE_DETECTED
    assert len(reuse_events()) == 1, "recorded once, however many losers"
    assert me(tokens["access"]) == 401


@pytest.mark.skipif(not POSTGRES, reason="needs concurrent connections (PostgreSQL)")
@pytest.mark.django_db(transaction=True)
def test_concurrent_refreshes_of_different_sessions_do_not_interfere(world: World) -> None:
    sessions = [login() for _ in range(4)]  # 4 logins + 4 refreshes: under THROTTLE_AUTH
    assert _race([tokens["refresh"] for tokens in sessions]) == [200] * 4
    assert reuse_events() == []
    assert set(RefreshTokenFamily.objects.values_list("generation", flat=True)) == {1}


def test_logout_needs_a_token_that_names_a_session(world: World) -> None:
    from django.conf import settings  # noqa: PLC0415

    tokens = login()
    legacy = token_claims(world.member_a, token_type="refresh")
    del legacy["fam"]
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
    response = client.post(
        "/api/v1/auth/logout/", {"refresh": forge_token(legacy, settings.SECRET_KEY)}
    )
    assert response.status_code == 400
    assert str(family_of(tokens["refresh"])).startswith("session ")
