"""A software WebAuthn authenticator for tests: real P-256 keys, real CBOR, real signatures.

It produces exactly what a browser hands back from ``navigator.credentials.create()``
(``none`` attestation) and ``.get()``, so the server's verification by
``py_webauthn`` runs end to end with nothing mocked.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04
FLAG_ATTESTED_DATA = 0x40


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class SoftAuthenticator:
    def __init__(self, rp_id: str = "localhost", origin: str = "http://localhost:8000") -> None:
        self.rp_id = rp_id
        self.origin = origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = 0

    @property
    def id(self) -> str:
        return b64url(self.credential_id)

    def _cose_public_key(self) -> bytes:
        numbers = self.key.public_key().public_numbers()
        return cbor2.dumps(
            {
                1: 2,  # kty: EC2
                3: -7,  # alg: ES256
                -1: 1,  # crv: P-256
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )

    def _client_data(self, kind: str, challenge: str, origin: str | None) -> bytes:
        return json.dumps(
            {
                "type": kind,
                "challenge": challenge,
                "origin": origin or self.origin,
                "crossOrigin": False,
            }
        ).encode()

    def _rp_hash(self, rp_id: str | None) -> bytes:
        return hashlib.sha256((rp_id or self.rp_id).encode()).digest()

    def register(
        self, options: dict[str, Any], *, origin: str | None = None, rp_id: str | None = None
    ) -> dict[str, Any]:
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        auth_data = (
            self._rp_hash(rp_id)
            + bytes([FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_ATTESTED_DATA])
            + struct.pack(">I", self.sign_count)
            + bytes(16)  # AAGUID: none
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + self._cose_public_key()
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": self.id,
            "rawId": self.id,
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "attestationObject": b64url(attestation),
                "transports": ["usb"],
            },
            "clientExtensionResults": {},
        }

    def sign(
        self,
        options: dict[str, Any],
        *,
        origin: str | None = None,
        count_by: int = 1,
        user_present: bool = True,
    ) -> dict[str, Any]:
        self.sign_count += count_by
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        flags = (FLAG_USER_PRESENT if user_present else 0) | FLAG_USER_VERIFIED
        auth_data = self._rp_hash(None) + bytes([flags]) + struct.pack(">I", self.sign_count)
        signature = self.key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": self.id,
            "rawId": self.id,
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "authenticatorData": b64url(auth_data),
                "signature": b64url(signature),
                "userHandle": None,
            },
            "clientExtensionResults": {},
        }
