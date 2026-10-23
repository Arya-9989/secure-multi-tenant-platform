"""OpenID Connect relying party: authorization code flow with PKCE (ADR 0004).

Kept small and explicit so every check is visible: discovery with an exact
issuer match, PKCE (S256), single-use state and nonce, the code exchange with
client authentication, and ID-token validation (signature from the JWKS, an
algorithm allow-list, ``iss``, ``aud``/``azp``, ``exp``/``iat``, ``nonce``).
Every HTTP call has a timeout. Failures raise :class:`SsoError` with a reason
that is audited but never shown to the caller.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

import jwt
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

# Asymmetric algorithms only: no "none", and no HMAC (whose key would be the
# client secret, letting anyone who knows it mint ID tokens).
ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384")
SCOPES = "openid email profile"
STATE_TTL_SECONDS = 600
HANDOFF_TTL_SECONDS = 60
_DISCOVERY_TTL_SECONDS = 3600
_JWKS_TTL_SECONDS = 300


class SsoError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.provider: Any = None  # set once the provider is known, for the audit trail


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def check_url(url: str) -> None:
    """IdP endpoints must use HTTPS (plain HTTP only when explicitly allowed for local IdPs)."""
    scheme = urllib.parse.urlsplit(url).scheme
    if scheme != "https" and not (scheme == "http" and settings.SSO_ALLOW_HTTP):
        raise SsoError("insecure_idp_url")


def http_json(
    url: str, *, form: dict[str, str] | None = None, basic: tuple[str, str] | None = None
) -> Any:
    """GET (or form-POST) ``url`` and decode its JSON, with a timeout."""
    check_url(url)
    headers = {"Accept": "application/json"}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if basic is not None:
        user, password = (urllib.parse.quote(part, safe="") for part in basic)
        headers["Authorization"] = (
            "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        )
    request = urllib.request.Request(url, data=data, headers=headers)  # noqa: S310 - checked above
    try:
        with urllib.request.urlopen(request, timeout=settings.SSO_HTTP_TIMEOUT_SECONDS) as response:  # noqa: S310
            return json.loads(response.read(1_000_000))
    except urllib.error.HTTPError as exc:
        logger.warning("IdP answered %s for %s", exc.code, url)
        raise SsoError("idp_error") from exc
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        logger.warning("IdP unreachable or malformed at %s: %s", url, exc)
        raise SsoError("idp_unreachable") from exc


@dataclass(frozen=True, slots=True)
class Discovery:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


def discover(issuer: str) -> Discovery:
    key = f"sso:discovery:{_digest(issuer)}"
    document = cache.get(key)
    if document is None:
        document = http_json(issuer.rstrip("/") + "/.well-known/openid-configuration")
        if not isinstance(document, dict):
            raise SsoError("bad_discovery")
        cache.set(key, document, timeout=_DISCOVERY_TTL_SECONDS)
    # Mix-up defence: the document must speak for exactly the issuer we trust.
    if document.get("issuer") != issuer:
        raise SsoError("issuer_mismatch")
    try:
        discovery = Discovery(
            issuer=issuer,
            authorization_endpoint=str(document["authorization_endpoint"]),
            token_endpoint=str(document["token_endpoint"]),
            jwks_uri=str(document["jwks_uri"]),
        )
    except KeyError as exc:
        raise SsoError("bad_discovery") from exc
    for url in (discovery.authorization_endpoint, discovery.token_endpoint, discovery.jwks_uri):
        check_url(url)
    return discovery


# ---------------------------------------------------------------- the flow
def begin(*, provider_id: str, organization_id: str, issuer: str, client_id: str) -> str:
    """Store a fresh state (with PKCE verifier and nonce); return the IdP's authorize URL."""
    discovery = discover(issuer)
    state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
    cache.set(
        f"sso:state:{_digest(state)}",
        {
            "provider": provider_id,
            "organization": organization_id,
            "verifier": verifier,
            "nonce": nonce,
        },
        timeout=STATE_TTL_SECONDS,
    )
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": settings.SSO_CALLBACK_URL,
            "scope": SCOPES,
            "state": state,
            "nonce": nonce,
            "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()),
            "code_challenge_method": "S256",
        }
    )
    separator = "&" if "?" in discovery.authorization_endpoint else "?"
    return f"{discovery.authorization_endpoint}{separator}{query}"


def consume_state(state: str) -> dict[str, str]:
    """The state's data, exactly once (``cache.delete`` decides the winner)."""
    key = f"sso:state:{_digest(state)}"
    data = cache.get(key) if state else None
    if not isinstance(data, dict) or not cache.delete(key):
        raise SsoError("unknown_state")
    return data


def exchange_code(
    discovery: Discovery, *, code: str, verifier: str, client_id: str, client_secret: str
) -> str:
    """Redeem the authorization code (with the PKCE verifier) for an ID token."""
    tokens = http_json(
        discovery.token_endpoint,
        form={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.SSO_CALLBACK_URL,
            "code_verifier": verifier,
        },
        basic=(client_id, client_secret),
    )
    id_token = tokens.get("id_token") if isinstance(tokens, dict) else None
    if not isinstance(id_token, str):
        raise SsoError("no_id_token")
    return id_token


def _signing_key(discovery: Discovery, kid: str | None) -> Any:
    key = f"sso:jwks:{_digest(discovery.jwks_uri)}"
    for refresh in (False, True):  # an unknown kid may mean the IdP rotated its keys
        jwks = None if refresh else cache.get(key)
        if jwks is None:
            jwks = http_json(discovery.jwks_uri)
            cache.set(key, jwks, timeout=_JWKS_TTL_SECONDS)
        try:
            keys = jwt.PyJWKSet.from_dict(jwks).keys
        except jwt.PyJWKSetError as exc:
            raise SsoError("bad_jwks") from exc
        for candidate in keys:
            if kid is None or candidate.key_id == kid:
                return candidate.key
    raise SsoError("unknown_signing_key")


def validate_id_token(
    discovery: Discovery, id_token: str, *, client_id: str, nonce: str
) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.InvalidTokenError as exc:
        raise SsoError("malformed_id_token") from exc
    algorithm = header.get("alg")
    if algorithm not in ALLOWED_ALGORITHMS:
        raise SsoError("disallowed_algorithm")
    key = _signing_key(discovery, header.get("kid"))
    try:
        claims: dict[str, Any] = jwt.decode(
            id_token,
            key,
            algorithms=[algorithm],
            audience=client_id,
            issuer=discovery.issuer,
            leeway=30,
            options={"require": ["iss", "aud", "exp", "iat", "sub"]},
        )
    except jwt.InvalidTokenError as exc:
        raise SsoError(f"invalid_id_token:{type(exc).__name__}") from exc
    audiences = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
    if len(audiences) > 1 and claims.get("azp") != client_id:
        raise SsoError("azp_mismatch")
    if not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
        raise SsoError("nonce_mismatch")
    return claims


def hand_off(user_id: str) -> str:
    """A one-time code the frontend exchanges for tokens (no tokens in URLs)."""
    code = secrets.token_urlsafe(32)
    cache.set(f"sso:handoff:{_digest(code)}", user_id, timeout=HANDOFF_TTL_SECONDS)
    return code


def redeem_hand_off(code: str) -> str | None:
    key = f"sso:handoff:{_digest(code)}"
    user_id = cache.get(key) if code else None
    if not isinstance(user_id, str) or not cache.delete(key):
        return None
    return user_id
