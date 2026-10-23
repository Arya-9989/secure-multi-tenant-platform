"""An in-process OpenID provider for tests: real RSA keys, real JWTs, real PKCE checks.

It answers discovery, JWKS and token requests the way an IdP would, and checks
what the platform sends it (the PKCE verifier against the challenge, the client
credentials, the redirect URI), so the tests prove both sides of the protocol.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
import warnings
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from apps.sso.oidc import SsoError


@dataclass
class Grant:
    client_id: str
    redirect_uri: str
    nonce: str
    challenge: str
    claims: dict[str, Any]


@dataclass
class FakeIdp:
    issuer: str
    client_id: str
    client_secret: str
    key: Any = field(default_factory=lambda: rsa.generate_private_key(65537, 2048))
    kid: str = "key-1"
    grants: dict[str, Grant] = field(default_factory=dict)
    token_requests: list[dict[str, Any]] = field(default_factory=list)
    discovery_overrides: dict[str, Any] = field(default_factory=dict)
    jwks_requests: int = 0

    # ------------------------------------------------------------ documents
    def discovery(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/protocol/openid-connect/auth",
            "token_endpoint": f"{self.issuer}/protocol/openid-connect/token",
            "jwks_uri": f"{self.issuer}/protocol/openid-connect/certs",
            **self.discovery_overrides,
        }

    def jwks(self) -> dict[str, Any]:
        jwk = RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        return {"keys": [{**jwk, "kid": self.kid, "alg": "RS256", "use": "sig"}]}

    # ------------------------------------------------------------ the browser leg
    def authorize(self, location: str, **claims: Any) -> dict[str, str]:
        """Play the user signing in at the IdP: returns the callback's query string."""
        query = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
        assert query["response_type"] == "code"
        assert query["code_challenge_method"] == "S256"
        assert "openid" in query["scope"].split()
        code = secrets.token_urlsafe(16)
        self.grants[code] = Grant(
            client_id=query["client_id"],
            redirect_uri=query["redirect_uri"],
            nonce=query["nonce"],
            challenge=query["code_challenge"],
            claims=claims,
        )
        return {"code": code, "state": query["state"]}

    # ------------------------------------------------------------ the back channel
    def id_token(self, grant: Grant) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": self.client_id,
            "sub": "subject-alice",
            "email": "admin@a.test",
            "email_verified": True,
            "nonce": grant.nonce,
            "iat": now,
            "exp": now + 300,
        }
        claims.update(grant.claims.pop("claims", {}))
        for name in [k for k, v in claims.items() if v is None]:
            del claims[name]
        header = {"kid": self.kid, **grant.claims.pop("header", {})}
        signer = grant.claims.pop("signer", None)
        if signer == "none":
            return jwt.encode(claims, "", algorithm="none", headers=header)
        if signer == "client-secret":  # HS256 with the shared secret: must be refused
            with warnings.catch_warnings():  # PyJWT rightly warns about the short key
                warnings.simplefilter("ignore")
                return jwt.encode(claims, self.client_secret, algorithm="HS256", headers=header)
        key = signer if signer is not None else self.key
        return jwt.encode(claims, key, algorithm="RS256", headers=header)

    def token(self, form: dict[str, str], basic: tuple[str, str] | None) -> dict[str, Any]:
        self.token_requests.append({"form": form, "basic": basic})
        grant = self.grants.pop(form.get("code", ""), None)
        if grant is None or basic != (self.client_id, self.client_secret):
            raise SsoError("idp_error")  # what a 400/401 from the IdP becomes
        verifier = form.get("code_verifier", "")
        computed = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
        if computed.decode() != grant.challenge or form["redirect_uri"] != grant.redirect_uri:
            raise SsoError("idp_error")
        return {"access_token": "opaque", "token_type": "Bearer", "id_token": self.id_token(grant)}

    def http_json(
        self, url: str, *, form: dict[str, str] | None = None, basic: tuple[str, str] | None = None
    ) -> Any:
        document = self.discovery()
        if url == self.issuer + "/.well-known/openid-configuration":
            return document
        if url == document["jwks_uri"]:
            self.jwks_requests += 1
            return self.jwks()
        if url == document["token_endpoint"] and form is not None:
            return self.token(form, basic)
        raise SsoError("idp_unreachable")
