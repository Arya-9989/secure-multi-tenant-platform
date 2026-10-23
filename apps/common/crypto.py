"""Encryption of secrets that must be readable again (TOTP seeds, OIDC client secrets).

Fernet (AES-128-CBC with HMAC-SHA256) through ``MultiFernet``: the first key of
``FIELD_ENCRYPTION_KEYS`` encrypts, every key decrypts, so keys can be rotated
by prepending a new one. Without configured keys one is derived from
``SECRET_KEY`` with HKDF, which ties these secrets to it.
"""

from __future__ import annotations

import base64
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings
from django.core.signals import setting_changed
from django.dispatch import receiver

__all__ = ["DecryptionError", "decrypt", "encrypt"]


class DecryptionError(Exception):
    """The value was not encrypted with any of the configured keys."""


def _derived_key() -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"secure-multi-tenant-platform",
        info=b"field-encryption",
    )
    return base64.urlsafe_b64encode(hkdf.derive(settings.SECRET_KEY.encode()))


@lru_cache(maxsize=1)
def _fernet() -> MultiFernet:
    keys: list[str] = settings.FIELD_ENCRYPTION_KEYS
    return MultiFernet([Fernet(key) for key in keys] or [Fernet(_derived_key())])


@receiver(setting_changed)
def _reset(*, setting: str, **kwargs: object) -> None:
    if setting in {"FIELD_ENCRYPTION_KEYS", "SECRET_KEY"}:
        _fernet.cache_clear()


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise DecryptionError from exc
