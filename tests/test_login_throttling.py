"""Per-account sign-in throttling with progressive delays (ADR 0003).

The attacker here is distributed: every request comes from a fresh IP, so the
per-IP limit never fires and only the per-account buckets stand in the way.
The other half of the story is the victim, who must still get into their own
devices however hard someone hammers their email.
"""

from __future__ import annotations

import io
import os
import threading
import time
from itertools import count
from typing import Any

import pytest
from django.core.management import call_command
from django.test import Client, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from apps.accounts import login_throttle
from apps.auditlogs.models import AuditAction, AuditLog
from tests.conftest import PASSWORD, World

pytestmark = pytest.mark.django_db

LOGIN = "/api/v1/auth/login/"
_ips = count(1)


class Clock:
    def __init__(self) -> None:
        self.now = time.time()

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Controls the time the throttle and the (local-memory) cache both read."""
    fake = Clock()
    monkeypatch.setattr(time, "time", lambda: fake.now)
    return fake


def attempt(email: str, password: str = "wrong", client: APIClient | None = None) -> Any:  # noqa: S107
    """One sign-in from a fresh IP address, like a botnet would."""
    ip = next(_ips)
    return (client or APIClient()).post(
        LOGIN,
        {"email": email, "password": password},
        REMOTE_ADDR=f"10.{ip // 65536 % 256}.{ip // 256 % 256}.{ip % 256}",
    )


def failures(email: str) -> list[AuditLog]:
    return list(AuditLog.objects.filter(action=AuditAction.LOGIN_FAILED, metadata__email=email))


# ---------------------------------------------------------------- progressive delays
def test_a_distributed_attack_meets_doubling_delays(world: World, clock: Clock) -> None:
    for _ in range(5):
        assert attempt("member@a.test").status_code == 401
    # The sixth is evaluated, and starts a 2-second delay before the next one.
    assert attempt("member@a.test").status_code == 401
    assert failures("member@a.test")[0].metadata["next_attempt_delay"] == 2

    refused = attempt("member@a.test")
    assert refused.status_code == 429
    assert refused["Retry-After"] == "2"
    clock.advance(2.1)
    assert attempt("member@a.test").status_code == 401  # evaluated; now 4 seconds
    clock.advance(3)
    assert attempt("member@a.test").status_code == 429
    clock.advance(1.1)
    assert attempt("member@a.test").status_code == 401  # evaluated; now 8 seconds
    assert len(failures("member@a.test")) == 8, "refused attempts are not evaluated"


def test_delays_double_up_to_a_cap_and_never_lock() -> None:
    assert [login_throttle.delay_for(n) for n in range(6)] == [0, 2, 4, 8, 16, 32]
    assert login_throttle.delay_for(9) == 512
    assert login_throttle.delay_for(10) == 900
    assert login_throttle.delay_for(10_000) == 900


def test_the_right_password_is_not_even_checked_during_a_delay(world: World, clock: Clock) -> None:
    for _ in range(6):
        attempt("member@a.test")
    response = attempt("member@a.test", PASSWORD)
    assert response.status_code == 429
    assert not AuditLog.objects.filter(action=AuditAction.LOGIN_SUCCEEDED).exists()
    clock.advance(2.1)
    assert attempt("member@a.test", PASSWORD).status_code == 200


def test_a_successful_sign_in_resets_the_count(world: World) -> None:
    for _ in range(4):
        attempt("member@a.test")
    assert attempt("member@a.test", PASSWORD).status_code == 200
    for _ in range(5):
        assert attempt("member@a.test").status_code == 401
    assert attempt("member@a.test").status_code == 401  # the sixth since the reset


def test_the_count_expires_with_its_window(world: World, clock: Clock) -> None:
    for _ in range(7):
        attempt("member@a.test")
    clock.advance(86_400 + 1)
    for _ in range(6):
        assert attempt("member@a.test").status_code == 401


def test_other_accounts_are_unaffected(world: World) -> None:
    for _ in range(8):
        attempt("member@a.test")
    assert attempt("admin@a.test", PASSWORD).status_code == 200


# ---------------------------------------------------------------- lockout DoS
def test_the_victim_still_gets_into_their_own_device(world: World) -> None:
    victim = APIClient()
    assert attempt("member@a.test", PASSWORD, victim).status_code == 200
    assert login_throttle.DEVICE_COOKIE in victim.cookies

    for _ in range(20):  # someone else, everywhere
        attempt("member@a.test")
    assert attempt("member@a.test", PASSWORD).status_code == 429, "new devices wait"
    assert attempt("member@a.test", PASSWORD, victim).status_code == 200, "known ones do not"


def test_a_stolen_device_token_buys_only_that_devices_budget(world: World) -> None:
    victim = APIClient()
    attempt("member@a.test", PASSWORD, victim)
    thief = APIClient()
    thief.cookies[login_throttle.DEVICE_COOKIE] = victim.cookies[login_throttle.DEVICE_COOKIE].value
    for _ in range(6):
        assert attempt("member@a.test", client=thief).status_code == 401
    assert attempt("member@a.test", client=thief).status_code == 429


def test_a_device_token_counts_only_for_its_own_account(world: World) -> None:
    alice_device = APIClient()
    attempt("admin@a.test", PASSWORD, alice_device)
    for _ in range(6):
        attempt("member@a.test")
    # Alice's device is a stranger to Bob's account.
    assert attempt("member@a.test", PASSWORD, alice_device).status_code == 429


@pytest.mark.parametrize(
    "cookie",
    ["", "garbage", "eyJhIjoiYWJjIiwiZCI6Inh4In0:1abc:forged", None],
    ids=["empty", "garbage", "forged-signature", "expired"],
)
def test_tampered_or_expired_device_tokens_are_strangers(
    world: World, clock: Clock, cookie: str | None
) -> None:
    client = APIClient()
    if cookie is None:  # a real token, past its trust period
        attempt("member@a.test", PASSWORD, client)
        clock.advance(91 * 86_400)
    else:
        client.cookies[login_throttle.DEVICE_COOKIE] = cookie
    for _ in range(6):
        attempt("member@a.test")
    assert attempt("member@a.test", PASSWORD, client).status_code == 429


def test_the_device_cookie_is_locked_down(world: World) -> None:
    response = attempt("member@a.test", PASSWORD)
    cookie = response.cookies[login_throttle.DEVICE_COOKIE]
    assert cookie["httponly"] is True
    assert cookie["samesite"] == "Strict"
    assert int(cookie["max-age"]) == 90 * 86_400
    assert cookie["secure"] is True  # follows DJANGO_SECURE_COOKIES
    with override_settings(SESSION_COOKIE_SECURE=False):
        insecure = attempt("member@a.test", PASSWORD).cookies[login_throttle.DEVICE_COOKIE]
        assert insecure["secure"] == ""
    assert response.json().keys() == {"access", "refresh"}, "the body is unchanged"


def test_a_returning_device_keeps_its_identity(world: World) -> None:
    client = APIClient()
    attempt("member@a.test", PASSWORD, client)
    first = client.cookies[login_throttle.DEVICE_COOKIE].value
    attempt("member@a.test", PASSWORD, client)
    key = login_throttle.account_key("member@a.test")
    second = client.cookies[login_throttle.DEVICE_COOKIE].value
    assert login_throttle.verify_device_token(first, key) == login_throttle.verify_device_token(
        second, key
    )


# ---------------------------------------------------------------- enumeration
def test_unknown_emails_are_throttled_exactly_like_real_ones(world: World) -> None:
    def transcript(email: str) -> list[tuple[Any, ...]]:
        responses = [attempt(email) for _ in range(8)]
        return [(r.status_code, r.json(), r.get("Retry-After")) for r in responses]

    assert transcript("member@a.test") == transcript("nobody@nowhere.test")


def test_failed_attempts_are_attributed_without_revealing_existence(world: World) -> None:
    for _ in range(6):
        attempt("member@a.test")
        attempt("nobody@nowhere.test")
    known, unknown = failures("member@a.test"), failures("nobody@nowhere.test")
    assert {event.organization for event in known} == {world.org_a}
    assert {event.organization for event in unknown} == {None}
    assert [e.metadata.get("next_attempt_delay") for e in known] == [
        e.metadata.get("next_attempt_delay") for e in unknown
    ]


# ---------------------------------------------------------------- races
def _burst(size: int) -> list[login_throttle.Decision]:
    barrier = threading.Barrier(size)
    decisions: list[login_throttle.Decision] = []
    lock = threading.Lock()

    def race() -> None:
        barrier.wait(timeout=10)
        decision = login_throttle.check("member@a.test")
        with lock:
            decisions.append(decision)

    threads = [threading.Thread(target=race) for _ in range(size)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert len(decisions) == size
    return decisions


@pytest.mark.parametrize(
    ("already", "free", "gated"),
    [(5, 0, 1), (3, 2, 1), (0, 5, 1)],
    ids=["at-the-limit", "near-the-limit", "fresh"],
)
def test_a_burst_gets_exactly_the_attempts_the_policy_allows(
    world: World, already: int, free: int, gated: int
) -> None:
    """Twenty parallel attempts get what twenty sequential ones would: the free
    attempts left, plus one that opens the first delay, which is not inflated."""
    for _ in range(already):
        login_throttle.check("member@a.test")
    decisions = _burst(20)
    allowed = [d for d in decisions if d.allowed]
    assert [d.delay for d in allowed if d.delay] == [2] * gated
    assert len(allowed) == free + gated
    assert all(d.retry_after >= 1 for d in decisions if not d.allowed)


# ---------------------------------------------------------------- admin and operators
def test_the_admin_shares_the_accounts_buckets(world: World) -> None:
    for _ in range(6):
        attempt("root@platform.test")
    response = Client().post(
        reverse("admin:login"), {"username": "root@platform.test", "password": PASSWORD}
    )
    assert response.status_code == 429
    assert "_auth_user_id" not in Client().session


def test_the_admin_sets_the_device_cookie_and_honours_it(world: World) -> None:
    browser = Client()
    url = reverse("admin:login")
    response = browser.post(url, {"username": "root@platform.test", "password": PASSWORD})
    assert response.status_code == 302
    assert login_throttle.DEVICE_COOKIE in response.cookies
    for _ in range(8):
        attempt("root@platform.test")
    returning = Client()  # a new session in the same browser: only the cookie carries over
    returning.cookies[login_throttle.DEVICE_COOKIE] = browser.cookies[
        login_throttle.DEVICE_COOKIE
    ].value
    again = returning.post(url, {"username": "root@platform.test", "password": PASSWORD})
    assert again.status_code == 302
    assert (
        Client().post(url, {"username": "root@platform.test", "password": PASSWORD}).status_code
        == 429
    )


def test_operators_can_clear_an_accounts_delay(world: World) -> None:
    for _ in range(7):
        attempt("member@a.test")
    assert attempt("member@a.test", PASSWORD).status_code == 429
    out = io.StringIO()
    call_command("clear_login_throttle", "Member@A.test", stdout=out)
    assert "Cleared" in out.getvalue()
    assert attempt("member@a.test", PASSWORD).status_code == 200


def test_a_request_without_an_email_is_a_validation_error(world: World) -> None:
    response = APIClient().post(LOGIN, {"password": "x"})
    assert response.status_code == 400


# ---------------------------------------------------------------- the production cache
REDIS_URL = os.environ.get("TEST_REDIS_URL", "")


@pytest.mark.skipif(not REDIS_URL, reason="set TEST_REDIS_URL to run against Redis")
@override_settings(
    CACHES={
        "default": {"BACKEND": "django.core.cache.backends.redis.RedisCache", "LOCATION": REDIS_URL}
    },
    LOGIN_ACCOUNT_BASE_DELAY_SECONDS=3,
)
def test_on_redis_bursts_are_atomic_and_delays_expire(world: World) -> None:
    """The compose stack keeps counters in Redis; its INCR and SET NX carry the policy."""
    from django.core.cache import cache  # noqa: PLC0415

    cache.clear()
    try:
        for _ in range(5):
            assert login_throttle.check("member@a.test").allowed
        barrier = threading.Barrier(16)
        allowed: list[bool] = []
        lock = threading.Lock()

        def race() -> None:
            barrier.wait(timeout=10)
            decision = login_throttle.check("member@a.test")
            with lock:
                allowed.append(decision.allowed)

        threads = [threading.Thread(target=race) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert sum(allowed) == 1
        time.sleep(3.2)  # the burst opened exactly one three-second delay, kept by Redis
        assert login_throttle.check("member@a.test").delay == 6
        login_throttle.clear("member@a.test")
        assert login_throttle.check("member@a.test").allowed
    finally:
        cache.clear()


def test_a_counter_that_expires_mid_check_is_recreated(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    from django.core.cache import cache  # noqa: PLC0415

    real_incr = cache.incr
    calls: list[str] = []

    def expired_once(key: str, delta: int = 1) -> int:
        calls.append(key)
        if len(calls) == 1:
            cache.delete(key)
            raise ValueError(key)
        return int(real_incr(key, delta))

    monkeypatch.setattr(cache, "incr", expired_once)
    assert login_throttle.check("member@a.test").allowed
    assert len(calls) == 2


def test_a_gate_that_ends_while_being_read_means_retry_now(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    from django.core.cache import cache  # noqa: PLC0415

    for _ in range(6):
        login_throttle.check("member@a.test")
    real_get = cache.get

    def gate_gone(key: str, default: Any = None) -> Any:
        return None if key.endswith(":gate") else real_get(key, default)

    monkeypatch.setattr(cache, "get", gate_gone)
    decision = login_throttle.check("member@a.test")
    assert (decision.allowed, decision.retry_after) == (False, 1)
