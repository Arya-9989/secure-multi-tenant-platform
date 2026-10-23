"""Per-account sign-in throttling with progressive delays (ADR 0003).

Complements the per-IP limit. Attempts are counted per *bucket*: the account,
or, for a client that proves it signed in to this account before (a device
token), that device alone. That way a stranger who hammers someone's email
slows down guessing without being able to keep the account's owner out of
their own devices.

In a bucket the first ``LOGIN_ACCOUNT_FREE_ATTEMPTS`` attempts are evaluated
freely; each later one starts a delay (doubling, capped) before the next can
be evaluated. Attempts during a delay are refused before the password is
checked. Unknown emails get buckets exactly like real ones.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import math
import secrets
import time
from dataclasses import dataclass

from django.conf import settings
from django.core import signing
from django.core.cache import cache
from django.http import HttpRequest, HttpResponseBase

from apps.accounts.models import normalize_email

logger = logging.getLogger(__name__)

DEVICE_COOKIE = "login_device"
_DEVICE_SALT = "apps.accounts.login_throttle.device"
_KEY_PREFIX = "login-throttle"


def account_key(email: str) -> str:
    """A stable, non-reversible key for an email (cache keys never hold addresses)."""
    return hmac.new(
        settings.SECRET_KEY.encode(), f"login:{normalize_email(email)}".encode(), hashlib.sha256
    ).hexdigest()[:32]


def delay_for(excess: int) -> int:
    """Seconds before the next attempt, after ``excess`` attempts beyond the free ones."""
    base: int = settings.LOGIN_ACCOUNT_BASE_DELAY_SECONDS
    cap: int = settings.LOGIN_ACCOUNT_MAX_DELAY_SECONDS
    if excess <= 0:
        return 0
    return int(min(cap, base * 2 ** min(excess - 1, 32)))


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    bucket: str
    retry_after: int = 0
    # The delay this (allowed) attempt starts for the next one; 0 within the free attempts.
    delay: int = 0


def _keys(bucket: str) -> tuple[str, str]:
    return f"{_KEY_PREFIX}:{bucket}:count", f"{_KEY_PREFIX}:{bucket}:gate"


def bucket_for(email: str, device_token: str | None) -> str:
    key = account_key(email)
    device = verify_device_token(device_token, key)
    return f"device:{device}" if device else f"account:{key}"


def _increment(key: str) -> int:
    cache.add(key, 0, timeout=settings.LOGIN_ACCOUNT_WINDOW_SECONDS)
    try:
        return int(cache.incr(key))
    except ValueError:  # expired between add() and incr()
        cache.add(key, 0, timeout=settings.LOGIN_ACCOUNT_WINDOW_SECONDS)
        return int(cache.incr(key))


def check(email: str, device_token: str | None = None) -> Decision:
    """Reserve one evaluated attempt for this sign-in, or refuse it.

    The count holds evaluated attempts only. A free attempt reserves its place
    with an atomic increment (and gives it back if a burst overshot the limit);
    a later one must win the atomic ``add`` of the delay gate, whose length
    follows from the evaluated count, so a burst cannot inflate it.
    """
    bucket = bucket_for(email, device_token)
    count_key, gate_key = _keys(bucket)
    free: int = settings.LOGIN_ACCOUNT_FREE_ATTEMPTS
    if int(cache.get(count_key) or 0) < free:
        if _increment(count_key) <= free:
            return Decision(allowed=True, bucket=bucket)
        cache.decr(count_key)  # a burst overshot the free attempts
    delay = delay_for(int(cache.get(count_key) or 0) - free + 1)
    # Exactly one attempt can open each delay; the gate's value is when it ends.
    if cache.add(gate_key, time.time() + delay, timeout=delay):
        _increment(count_key)
        return Decision(allowed=True, bucket=bucket, delay=delay)
    ends_at = cache.get(gate_key)
    retry_after = max(1, math.ceil(ends_at - time.time())) if ends_at else 1
    logger.warning("Sign-in refused by the per-account throttle", extra={"bucket": bucket})
    return Decision(allowed=False, bucket=bucket, retry_after=retry_after)


def succeeded(decision: Decision) -> None:
    """A correct sign-in clears its bucket."""
    cache.delete_many(list(_keys(decision.bucket)))


def clear(email: str) -> None:
    """Operator action: forget an account's failed attempts (not its devices')."""
    cache.delete_many(list(_keys(f"account:{account_key(email)}")))


# ---------------------------------------------------------------- device tokens
def issue_device_token(email: str, existing: str | None = None) -> str:
    """A token proving this client signed in to this account (kept if already valid)."""
    key = account_key(email)
    device = verify_device_token(existing, key) or secrets.token_urlsafe(16)
    return signing.dumps({"a": key, "d": device}, salt=_DEVICE_SALT, compress=True)


def verify_device_token(token: str | None, key: str) -> str | None:
    """The device ID if ``token`` is a valid, unexpired device token for this account."""
    if not token:
        return None
    try:
        payload = signing.loads(
            token, salt=_DEVICE_SALT, max_age=settings.LOGIN_DEVICE_TRUST_DAYS * 86_400
        )
    except signing.BadSignature:
        return None
    if not isinstance(payload, dict) or not hmac.compare_digest(str(payload.get("a")), key):
        return None
    device = payload.get("d")
    return device if isinstance(device, str) and device else None


def device_token_from(request: HttpRequest) -> str | None:
    return request.COOKIES.get(DEVICE_COOKIE)


def set_device_cookie(response: HttpResponseBase, request: HttpRequest, email: str) -> None:
    response.set_cookie(
        DEVICE_COOKIE,
        issue_device_token(email, device_token_from(request)),
        max_age=settings.LOGIN_DEVICE_TRUST_DAYS * 86_400,
        secure=settings.SESSION_COOKIE_SECURE,
        httponly=True,
        samesite="Strict",
    )
