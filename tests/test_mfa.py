"""Multi-factor authentication: TOTP, WebAuthn and recovery codes (ADR 0004).

TOTP is checked against the RFCs' own test vectors. WebAuthn runs end to end
through ``py_webauthn`` with a software authenticator (real keys, real CBOR,
real signatures). Every way of using a factor twice is tried.
"""

from __future__ import annotations

import re
import threading
import time
from typing import Any

import pytest
from django.db import connections
from django.test import Client
from django.urls import reverse
from rest_framework.test import APIClient

from apps.accounts import login_throttle
from apps.accounts.models import RefreshTokenFamily, User
from apps.auditlogs.models import AuditAction, AuditLog
from apps.common import crypto
from apps.common.throttling import ClientScopedRateThrottle
from apps.mfa import services as mfa
from apps.mfa import totp
from apps.mfa.models import RecoveryCode, TotpDevice, WebAuthnCredential
from tests.conftest import PASSWORD, POSTGRES, ClientFactory, World
from tests.soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.django_db

LOGIN = "/api/v1/auth/login/"
VERIFY = "/api/v1/auth/mfa/verify/"


@pytest.fixture(autouse=True)
def _no_per_ip_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """These tests make many credential requests from one address. The per-IP limit
    is tested in test_auth.py; the per-account one stays on here."""
    monkeypatch.setattr(ClientScopedRateThrottle, "allow_request", lambda *a: True)


# ---------------------------------------------------------------- RFC test vectors
RFC4226_SECRET = b"12345678901234567890"
RFC4226_HOTP = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]  # fmt: skip


def test_hotp_matches_rfc_4226_appendix_d() -> None:
    assert [totp.hotp(RFC4226_SECRET, counter) for counter in range(10)] == RFC4226_HOTP


@pytest.mark.parametrize(
    ("unix_time", "sha1", "sha256"),
    [
        (59, "94287082", "46119246"),
        (1111111109, "07081804", "68084774"),
        (1111111111, "14050471", "67062674"),
        (1234567890, "89005924", "91819424"),
        (2000000000, "69279037", "90698825"),
        (20000000000, "65353130", "77737706"),
    ],
)
def test_totp_matches_rfc_6238_appendix_b(unix_time: int, sha1: str, sha256: str) -> None:
    assert totp.totp(RFC4226_SECRET, unix_time, digits=8) == sha1
    secret_256 = b"12345678901234567890123456789012"
    assert totp.totp(secret_256, unix_time, digits=8, digest="sha256") == sha256


def test_codes_are_accepted_one_step_either_side_and_no_further() -> None:
    secret, now = totp.new_secret(), 1_800_000_000.0
    step = totp.time_step(now)
    for drift in (-1, 0, 1):
        assert totp.matching_step(secret, totp.hotp(secret, step + drift), now) == step + drift
    for drift in (-2, 2):
        assert totp.matching_step(secret, totp.hotp(secret, step + drift), now) is None
    for junk in ("", "12345", "1234567", "abcdef", "12 345"):
        assert totp.matching_step(secret, junk, now) is None


def test_the_provisioning_uri_is_what_authenticator_apps_expect() -> None:
    uri = totp.provisioning_uri(b"\x00" * 20, "alice@acme.test", "Secure Platform")
    assert uri.startswith("otpauth://totp/Secure%20Platform%3Aalice%40acme.test?")
    assert "secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" in uri
    assert "algorithm=SHA1&digits=6&period=30" in uri


# ---------------------------------------------------------------- helpers
def authed(user: User, client_for: ClientFactory) -> APIClient:
    return client_for(user)


def current_code(user: User, steps: int = 0) -> str:
    device = TotpDevice.objects.get(user=user)
    secret = bytes.fromhex(crypto.decrypt(device.secret_encrypted))
    return totp.hotp(secret, totp.time_step(time.time()) + steps)


def enrol_totp(user: User, client_for: ClientFactory) -> list[str]:
    client = authed(user, client_for)
    assert client.post("/api/v1/auth/mfa/totp/", {"password": PASSWORD}).status_code == 200
    response = client.post("/api/v1/auth/mfa/totp/confirm/", {"code": current_code(user, -1)})
    assert response.status_code == 200, response.content
    codes: list[str] = response.json()["recovery_codes"]
    return codes


def password_step(email: str = "member@a.test", client: APIClient | None = None) -> Any:
    response = (client or APIClient()).post(LOGIN, {"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.content
    return response.json()


def second_step(token: str, code: str, client: APIClient | None = None) -> Any:
    return (client or APIClient()).post(VERIFY, {"mfa_token": token, "code": code})


def mfa_failures() -> int:
    return AuditLog.objects.filter(action=AuditAction.MFA_FAILED).count()


# ---------------------------------------------------------------- TOTP enrolment
def test_setting_up_an_authenticator_app(world: World, client_for: ClientFactory) -> None:
    client = authed(world.member_a, client_for)
    assert client.post("/api/v1/auth/mfa/totp/", {"password": "wrong"}).status_code == 400
    setup = client.post("/api/v1/auth/mfa/totp/", {"password": PASSWORD}).json()
    assert re.fullmatch(r"[A-Z2-7]{32}", setup["secret"])
    assert setup["secret"] in setup["otpauth_uri"]

    device = TotpDevice.objects.get(user=world.member_a)
    assert setup["secret"] not in device.secret_encrypted, "encrypted at rest"
    assert device.confirmed_at is None
    assert not mfa.has_mfa(world.member_a), "nothing changes until a first code"

    bad = client.post("/api/v1/auth/mfa/totp/confirm/", {"code": "000000"})
    assert bad.status_code == 400
    codes = client.post(
        "/api/v1/auth/mfa/totp/confirm/", {"code": current_code(world.member_a)}
    ).json()["recovery_codes"]
    assert len(codes) == 10
    assert all(
        re.fullmatch(r"[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}", c) for c in codes
    )
    assert len(set(codes)) == 10
    stored = set(
        RecoveryCode.objects.filter(user=world.member_a).values_list("code_hash", flat=True)
    )
    assert not stored & set(codes), "only digests are stored"

    status = client.get("/api/v1/auth/mfa/").json()
    assert status["enabled"] is True
    assert status["totp"] == {"confirmed": True}
    assert status["recovery_codes_remaining"] == 10
    assert AuditLog.objects.filter(action=AuditAction.MFA_TOTP_ENABLED).count() == 1
    again = client.post("/api/v1/auth/mfa/totp/", {"password": PASSWORD})
    assert again.status_code == 400, "one app at a time: disable first"


def test_confirming_without_a_pending_setup_is_refused(
    world: World, client_for: ClientFactory
) -> None:
    response = authed(world.member_a, client_for).post(
        "/api/v1/auth/mfa/totp/confirm/", {"code": "123456"}
    )
    assert response.status_code == 400


# ---------------------------------------------------------------- signing in with TOTP
def test_a_password_alone_no_longer_signs_in(world: World, client_for: ClientFactory) -> None:
    enrol_totp(world.member_a, client_for)
    sessions_before = RefreshTokenFamily.objects.count()
    first = password_step()
    assert first == {
        "mfa_required": True,
        "mfa_token": first["mfa_token"],
        "methods": ["totp", "recovery_code"],
    }
    assert RefreshTokenFamily.objects.count() == sessions_before, "no session yet"
    assert not AuditLog.objects.filter(action=AuditAction.LOGIN_SUCCEEDED).exists()

    response = second_step(first["mfa_token"], current_code(world.member_a))
    assert response.status_code == 200, response.content
    assert set(response.json()) == {"access", "refresh"}
    assert "login_device" in response.cookies
    event = AuditLog.objects.get(action=AuditAction.LOGIN_SUCCEEDED)
    assert (event.actor, event.metadata) == (world.member_a, {"mfa": "totp"})
    # The challenge is spent.
    assert second_step(first["mfa_token"], current_code(world.member_a, 1)).status_code == 401


def test_a_totp_code_works_once(world: World, client_for: ClientFactory) -> None:
    enrol_totp(world.member_a, client_for)
    code = current_code(world.member_a)
    assert second_step(password_step()["mfa_token"], code).status_code == 200
    replay = second_step(password_step()["mfa_token"], code)
    assert replay.status_code == 401
    assert replay.json() == {"detail": "Invalid or expired code."}
    assert mfa_failures() == 1


def test_an_older_code_is_dead_once_a_newer_one_was_used(
    world: World, client_for: ClientFactory
) -> None:
    enrol_totp(world.member_a, client_for)
    assert (
        second_step(password_step()["mfa_token"], current_code(world.member_a, 1)).status_code
        == 200
    )
    stale = current_code(world.member_a, 0)
    assert second_step(password_step()["mfa_token"], stale).status_code == 401


@pytest.mark.skipif(not POSTGRES, reason="needs concurrent connections (PostgreSQL)")
@pytest.mark.django_db(transaction=True)
def test_one_code_raced_from_two_challenges_signs_in_once(
    world: World, client_for: ClientFactory
) -> None:
    enrol_totp(world.member_a, client_for)
    tokens = [password_step()["mfa_token"] for _ in range(3)]  # within the account budget
    code = current_code(world.member_a)
    barrier = threading.Barrier(len(tokens))
    statuses: list[int] = []
    lock = threading.Lock()

    def verify(token: str) -> None:
        try:
            barrier.wait(timeout=10)
            status = second_step(token, code).status_code
            with lock:
                statuses.append(status)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=verify, args=(t,)) for t in tokens]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert sorted(statuses) == [200, 401, 401]


def test_a_challenge_allows_five_attempts(world: World, client_for: ClientFactory) -> None:
    enrol_totp(world.member_a, client_for)
    token = password_step()["mfa_token"]
    for _ in range(5):
        assert second_step(token, "000000").status_code == 401
    login_throttle.clear("member@a.test")  # isolate the per-challenge limit
    assert second_step(token, current_code(world.member_a)).status_code == 401, "spent"


def test_second_factor_guesses_count_against_the_account(
    world: World, client_for: ClientFactory
) -> None:
    """A correct password does not reset the per-account bucket (ADR 0003)."""
    enrol_totp(world.member_a, client_for)
    statuses = []
    for _ in range(3):
        token = password_step()["mfa_token"]  # attempts 1, 3, 5
        statuses.append(second_step(token, "000000").status_code)  # 2, 4, 6 (opens a delay)
    assert statuses == [401, 401, 401]
    response = APIClient().post(LOGIN, {"email": "member@a.test", "password": PASSWORD})
    assert response.status_code == 429


def test_unknown_or_expired_challenges_are_refused(world: World) -> None:
    assert second_step("not-a-token", "123456").status_code == 401
    assert (
        APIClient().post("/api/v1/auth/mfa/webauthn/begin/", {"mfa_token": "nope"}).status_code
        == 401
    )


def test_a_challenge_dies_with_the_account(world: World, client_for: ClientFactory) -> None:
    enrol_totp(world.member_a, client_for)
    token = password_step()["mfa_token"]
    User.objects.filter(pk=world.member_a.pk).update(is_active=False)
    assert second_step(token, current_code(world.member_a)).status_code == 401


# ---------------------------------------------------------------- recovery codes
def test_a_recovery_code_signs_in_exactly_once(world: World, client_for: ClientFactory) -> None:
    codes = enrol_totp(world.member_a, client_for)
    sloppy = codes[0].lower().replace("-", " ")  # typed by hand
    response = second_step(password_step()["mfa_token"], sloppy)
    assert response.status_code == 200
    assert AuditLog.objects.get(action=AuditAction.LOGIN_SUCCEEDED).metadata == {
        "mfa": "recovery_code"
    }
    assert second_step(password_step()["mfa_token"], codes[0]).status_code == 401
    assert mfa.status(world.member_a)["recovery_codes_remaining"] == 9


def test_regenerating_recovery_codes_kills_the_old_ones(
    world: World, client_for: ClientFactory
) -> None:
    old = enrol_totp(world.member_a, client_for)
    client = authed(world.member_a, client_for)
    url = "/api/v1/auth/mfa/recovery-codes/"
    assert client.post(url, {"password": "wrong"}).status_code == 400
    new = client.post(url, {"password": PASSWORD}).json()["recovery_codes"]
    assert not set(new) & set(old)
    assert second_step(password_step()["mfa_token"], old[1]).status_code == 401
    assert second_step(password_step()["mfa_token"], new[1]).status_code == 200


def test_recovery_codes_need_a_second_factor(world: World, client_for: ClientFactory) -> None:
    response = authed(world.member_a, client_for).post(
        "/api/v1/auth/mfa/recovery-codes/", {"password": PASSWORD}
    )
    assert response.status_code == 400


# ---------------------------------------------------------------- disabling
def test_disabling_the_last_factor_turns_mfa_off(world: World, client_for: ClientFactory) -> None:
    enrol_totp(world.member_a, client_for)
    client = authed(world.member_a, client_for)
    url = "/api/v1/auth/mfa/totp/disable/"
    assert client.post(url, {"password": "wrong"}).status_code == 400
    assert client.post(url, {"password": PASSWORD}).status_code == 204
    assert not RecoveryCode.objects.filter(user=world.member_a).exists()
    assert set(password_step()) == {"access", "refresh"}
    assert client.post(url, {"password": PASSWORD}).status_code == 400, "nothing left to disable"
    assert AuditLog.objects.filter(action=AuditAction.MFA_TOTP_DISABLED).count() == 1


# ---------------------------------------------------------------- WebAuthn
def register_key(user: User, client_for: ClientFactory, key: SoftAuthenticator) -> Any:
    client = authed(user, client_for)
    options = client.post("/api/v1/auth/mfa/webauthn/register/", {"password": PASSWORD}).json()
    return client.post(
        "/api/v1/auth/mfa/webauthn/register/complete/",
        {"credential": key.register(options), "name": "YubiKey"},
        format="json",
    )


def webauthn_step(token: str, key: SoftAuthenticator, **assertion: Any) -> Any:
    options = APIClient().post("/api/v1/auth/mfa/webauthn/begin/", {"mfa_token": token}).json()
    return APIClient().post(
        "/api/v1/auth/mfa/webauthn/complete/",
        {"mfa_token": token, "credential": key.sign(options, **assertion)},
        format="json",
    )


def test_registering_and_signing_in_with_a_security_key(
    world: World, client_for: ClientFactory
) -> None:
    key = SoftAuthenticator()
    response = register_key(world.member_a, client_for, key)
    assert response.status_code == 201, response.content
    assert len(response.json()["recovery_codes"]) == 10, "first factor: codes issued"
    stored = WebAuthnCredential.objects.get(user=world.member_a)
    assert (stored.credential_id, stored.name, stored.transports) == (key.id, "YubiKey", ["usb"])

    first = password_step()
    assert first["methods"] == ["webauthn", "recovery_code"]
    options = (
        APIClient()
        .post("/api/v1/auth/mfa/webauthn/begin/", {"mfa_token": first["mfa_token"]})
        .json()
    )
    assert options["rpId"] == "localhost"
    assert [c["id"] for c in options["allowCredentials"]] == [key.id]
    signed_in = APIClient().post(
        "/api/v1/auth/mfa/webauthn/complete/",
        {"mfa_token": first["mfa_token"], "credential": key.sign(options)},
        format="json",
    )
    assert signed_in.status_code == 200, signed_in.content
    assert AuditLog.objects.get(action=AuditAction.LOGIN_SUCCEEDED).metadata == {"mfa": "webauthn"}
    stored.refresh_from_db()
    assert (stored.sign_count, stored.last_used_at is not None) == (1, True)


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param({"origin": "https://evil.example"}, id="wrong-origin"),
        pytest.param({"user_present": False}, id="no-user-presence"),
        pytest.param({"count_by": 0}, id="counter-did-not-advance"),
    ],
)
def test_bad_security_key_answers_are_refused(
    world: World, client_for: ClientFactory, tamper: dict[str, Any]
) -> None:
    key = SoftAuthenticator()
    register_key(world.member_a, client_for, key)
    assert webauthn_step(password_step()["mfa_token"], key).status_code == 200  # count 1
    response = webauthn_step(password_step()["mfa_token"], key, **tamper)
    assert response.status_code == 401
    assert mfa_failures() == 1


def test_a_replayed_assertion_is_refused(world: World, client_for: ClientFactory) -> None:
    key = SoftAuthenticator()
    register_key(world.member_a, client_for, key)
    token = password_step()["mfa_token"]
    options = APIClient().post("/api/v1/auth/mfa/webauthn/begin/", {"mfa_token": token}).json()
    captured = key.sign(options)
    body = {"mfa_token": token, "credential": captured}
    url = "/api/v1/auth/mfa/webauthn/complete/"
    assert APIClient().post(url, body, format="json").status_code == 200
    # Same answer, a fresh sign-in: the challenge differs, so it is refused.
    token = password_step()["mfa_token"]
    APIClient().post("/api/v1/auth/mfa/webauthn/begin/", {"mfa_token": token})
    response = APIClient().post(url, {"mfa_token": token, "credential": captured}, format="json")
    assert response.status_code == 401


def test_a_webauthn_challenge_is_answered_once(world: World, client_for: ClientFactory) -> None:
    key = SoftAuthenticator()
    register_key(world.member_a, client_for, key)
    token = password_step()["mfa_token"]
    options = APIClient().post("/api/v1/auth/mfa/webauthn/begin/", {"mfa_token": token}).json()
    url = "/api/v1/auth/mfa/webauthn/complete/"
    wrong = key.sign(options, origin="https://evil.example")
    assert (
        APIClient().post(url, {"mfa_token": token, "credential": wrong}, format="json").status_code
        == 401
    )
    right = key.sign(options)  # the old challenge, now burnt
    assert (
        APIClient().post(url, {"mfa_token": token, "credential": right}, format="json").status_code
        == 401
    )


def test_someone_elses_security_key_does_not_sign_you_in(
    world: World, client_for: ClientFactory
) -> None:
    mine, theirs = SoftAuthenticator(), SoftAuthenticator()
    register_key(world.member_a, client_for, mine)
    register_key(world.admin_a, client_for, theirs)
    assert webauthn_step(password_step()["mfa_token"], theirs).status_code == 401


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param({"origin": "https://evil.example"}, id="wrong-origin"),
        pytest.param({"rp_id": "evil.example"}, id="wrong-rp-id"),
    ],
)
def test_bad_registrations_are_refused(
    world: World, client_for: ClientFactory, tamper: dict[str, Any]
) -> None:
    client = authed(world.member_a, client_for)
    options = client.post("/api/v1/auth/mfa/webauthn/register/", {"password": PASSWORD}).json()
    response = client.post(
        "/api/v1/auth/mfa/webauthn/register/complete/",
        {"credential": SoftAuthenticator().register(options, **tamper)},
        format="json",
    )
    assert response.status_code == 400
    assert not WebAuthnCredential.objects.exists()


def test_registration_needs_a_fresh_challenge_and_a_new_key(
    world: World, client_for: ClientFactory
) -> None:
    client = authed(world.member_a, client_for)
    url = "/api/v1/auth/mfa/webauthn/register/complete/"
    key = SoftAuthenticator()
    no_begin = client.post(url, {"credential": key.register({"challenge": "AAAA"})}, format="json")
    assert no_begin.status_code == 400
    assert register_key(world.member_a, client_for, key).status_code == 201
    again = register_key(world.member_a, client_for, key)
    assert again.status_code == 400, "the same authenticator twice"
    assert client.post("/api/v1/auth/mfa/webauthn/register/", {"password": "x"}).status_code == 400


def test_removing_a_security_key(world: World, client_for: ClientFactory) -> None:
    key = SoftAuthenticator()
    register_key(world.member_a, client_for, key)
    credential = WebAuthnCredential.objects.get(user=world.member_a)
    client = authed(world.member_a, client_for)
    url = f"/api/v1/auth/mfa/webauthn/{credential.pk}/remove/"
    assert client.post(url, {"password": "wrong"}).status_code == 400
    assert client.post(url, {"password": PASSWORD}).status_code == 204
    assert not mfa.has_mfa(world.member_a)
    assert not RecoveryCode.objects.filter(user=world.member_a).exists()
    assert AuditLog.objects.filter(action=AuditAction.MFA_WEBAUTHN_REMOVED).count() == 1


@pytest.mark.parametrize("owner", ["admin_a", "member_b"], ids=["same-tenant", "other-tenant"])
def test_a_foreign_security_key_is_not_found(
    world: World, client_for: ClientFactory, owner: str
) -> None:
    """Another user's key ID answers 404, exactly like a key that does not exist."""
    register_key(getattr(world, owner), client_for, SoftAuthenticator())
    foreign = WebAuthnCredential.objects.get(user=getattr(world, owner))
    client = authed(world.member_a, client_for)
    response = client.post(
        f"/api/v1/auth/mfa/webauthn/{foreign.pk}/remove/", {"password": PASSWORD}
    )
    missing = client.post(
        "/api/v1/auth/mfa/webauthn/00000000-0000-0000-0000-000000000000/remove/",
        {"password": PASSWORD},
    )
    assert response.status_code == missing.status_code == 404
    assert response.json() == missing.json()
    assert WebAuthnCredential.objects.filter(pk=foreign.pk).exists()


def test_status_lists_only_your_own_factors(world: World, client_for: ClientFactory) -> None:
    register_key(world.admin_a, client_for, SoftAuthenticator())
    status = authed(world.member_a, client_for).get("/api/v1/auth/mfa/").json()
    assert status == {"enabled": False, "totp": None, "webauthn": [], "recovery_codes_remaining": 0}


# ---------------------------------------------------------------- admin reset
def test_an_admin_resets_a_members_factors(world: World, client_for: ClientFactory) -> None:
    enrol_totp(world.member_a, client_for)
    register_key(world.member_a, client_for, SoftAuthenticator())
    session = authed(world.member_a, client_for)
    response = client_for(world.admin_a).post(reverse("user-reset-mfa", args=[world.member_a.pk]))
    assert response.status_code == 204
    assert not mfa.has_mfa(world.member_a)
    assert not RecoveryCode.objects.filter(user=world.member_a).exists()
    assert session.get("/api/v1/auth/me/").status_code == 401, "their sessions end"
    event = AuditLog.objects.get(action=AuditAction.MFA_RESET)
    assert (event.actor, event.target_id) == (world.admin_a, str(world.member_a.pk))


def test_admins_cannot_reset_their_own_factors(world: World, client_for: ClientFactory) -> None:
    enrol_totp(world.admin_a, client_for)
    response = client_for(world.admin_a).post(reverse("user-reset-mfa", args=[world.admin_a.pk]))
    assert response.status_code == 403
    assert mfa.has_mfa(world.admin_a)


def test_a_foreign_admin_cannot_reset_your_factors(world: World, client_for: ClientFactory) -> None:
    enrol_totp(world.member_a, client_for)
    response = client_for(world.admin_b).post(reverse("user-reset-mfa", args=[world.member_a.pk]))
    assert response.status_code == 404
    assert mfa.has_mfa(world.member_a)


# ---------------------------------------------------------------- the Django admin
def test_the_admin_asks_for_the_second_factor(world: World, client_for: ClientFactory) -> None:
    codes = enrol_totp(world.super_admin, client_for)
    url = reverse("admin:login")
    form = {"username": "root@platform.test", "password": PASSWORD}
    page = Client().get(url).content.decode()
    assert 'name="otp"' in page
    assert 'autocomplete="one-time-code"' in page

    without = Client().post(url, form)
    assert without.status_code == 200
    assert "multi-factor authentication" in without.content.decode()
    assert Client().post(url, {**form, "otp": "000000"}).status_code == 200
    assert Client().post(url, {**form, "otp": current_code(world.super_admin)}).status_code == 302
    assert Client().post(url, {**form, "otp": codes[0]}).status_code == 302
    assert Client().post(url, {**form, "otp": codes[0]}).status_code == 200, "used up"
    assert (
        AuditLog.objects.filter(action=AuditAction.LOGIN_FAILED, metadata__channel="admin").count()
        == 3
    )


def test_the_admin_form_is_unchanged_for_accounts_without_mfa(world: World) -> None:
    response = Client().post(
        reverse("admin:login"), {"username": "root@platform.test", "password": PASSWORD}
    )
    assert response.status_code == 302


# ---------------------------------------------------------------- encryption at rest
def test_field_encryption_keys_rotate(settings: Any) -> None:
    from cryptography.fernet import Fernet  # noqa: PLC0415

    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    settings.FIELD_ENCRYPTION_KEYS = [old]
    token = crypto.encrypt("seed")
    settings.FIELD_ENCRYPTION_KEYS = [new, old]  # prepend the new key
    assert crypto.decrypt(token) == "seed"
    assert crypto.decrypt(crypto.encrypt("seed")) == "seed"
    settings.FIELD_ENCRYPTION_KEYS = [new]  # the old key retired
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(token)


def test_mfa_models_describe_themselves(world: World, client_for: ClientFactory) -> None:
    enrol_totp(world.member_a, client_for)
    register_key(world.member_a, client_for, SoftAuthenticator())
    assert str(TotpDevice.objects.get()) == f"TOTP for {world.member_a.pk}"
    assert str(WebAuthnCredential.objects.get()) == f"YubiKey ({world.member_a.pk})"
    assert str(RecoveryCode.objects.first()) == f"recovery code of {world.member_a.pk}"


def test_unknown_transports_from_old_browsers_are_ignored(
    world: World, client_for: ClientFactory
) -> None:
    key = SoftAuthenticator()
    register_key(world.member_a, client_for, key)
    WebAuthnCredential.objects.update(transports=["usb", "carrier-pigeon"])
    options = (
        APIClient()
        .post("/api/v1/auth/mfa/webauthn/begin/", {"mfa_token": password_step()["mfa_token"]})
        .json()
    )
    assert options["allowCredentials"][0]["transports"] == ["usb"]
