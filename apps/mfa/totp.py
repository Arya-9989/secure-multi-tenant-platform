"""Time-based one-time passwords, straight from RFC 6238 (and RFC 4226's HOTP).

HMAC-SHA1, 6 digits, 30-second steps: what every authenticator app supports.
Checked against the RFC's test vectors in ``tests/test_mfa.py``. Replay
protection lives in the caller: :func:`matching_step` returns the time step a
code belongs to, and the device accepts each step at most once.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from urllib.parse import quote, urlencode

STEP_SECONDS = 30
DIGITS = 6
SECRET_BYTES = 20  # 160 bits, the size RFC 4226 recommends for HMAC-SHA1
ALLOWED_DRIFT_STEPS = 1


def new_secret() -> bytes:
    return secrets.token_bytes(SECRET_BYTES)


def hotp(secret: bytes, counter: int, digits: int = DIGITS, digest: str = "sha1") -> str:
    """RFC 4226 section 5.3: dynamic truncation of HMAC(secret, counter)."""
    mac = hmac.new(secret, struct.pack(">Q", counter), getattr(hashlib, digest)).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10**digits).zfill(digits)


def time_step(unix_time: float) -> int:
    return int(unix_time // STEP_SECONDS)


def totp(secret: bytes, unix_time: float, digits: int = DIGITS, digest: str = "sha1") -> str:
    return hotp(secret, time_step(unix_time), digits, digest)


def matching_step(secret: bytes, code: str, unix_time: float) -> int | None:
    """The time step ``code`` is valid for, allowing one step of clock drift."""
    if len(code) != DIGITS or not code.isdigit():
        return None
    current = time_step(unix_time)
    match = None
    for step in range(current - ALLOWED_DRIFT_STEPS, current + ALLOWED_DRIFT_STEPS + 1):
        # Compare every candidate, in constant time, so timing reveals nothing.
        if hmac.compare_digest(hotp(secret, step), code):
            match = step
    return match


def encode_secret(secret: bytes) -> str:
    return base64.b32encode(secret).decode().rstrip("=")


def provisioning_uri(secret: bytes, account: str, issuer: str) -> str:
    """The ``otpauth://`` URI authenticator apps scan as a QR code."""
    label = quote(f"{issuer}:{account}")
    query = urlencode(
        {
            "secret": encode_secret(secret),
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": DIGITS,
            "period": STEP_SECONDS,
        }
    )
    return f"otpauth://totp/{label}?{query}"
