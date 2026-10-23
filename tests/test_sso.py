"""SSO via OpenID Connect, configured per organization (ADR 0004).

The IdP is :mod:`tests.fake_idp`: real RSA keys and JWTs, and it checks the PKCE
verifier, client credentials and redirect URI the platform sends. The browser is
played by the test. Every ID-token check is attacked one at a time, and so is
the boundary between tenants: one organization's IdP must never sign anybody
into another organization.
"""

from __future__ import annotations

import http.server
import json
import threading
import time
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from apps.accounts.models import User
from apps.auditlogs.models import AuditAction, AuditLog
from apps.common import crypto
from apps.common.throttling import ClientScopedRateThrottle
from apps.organizations.models import Organization
from apps.sso import oidc
from apps.sso.models import OidcProvider, SsoIdentity
from tests.conftest import ClientFactory, World
from tests.fake_idp import FakeIdp

pytestmark = pytest.mark.django_db

CALLBACK = "/api/v1/auth/sso/callback/"
FOREIGN_KEY = rsa.generate_private_key(65537, 2048)
EXCHANGE = "/api/v1/auth/sso/exchange/"


@pytest.fixture(autouse=True)
def _no_per_ip_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Many credential requests from one address; the per-IP limit is tested elsewhere."""
    monkeypatch.setattr(ClientScopedRateThrottle, "allow_request", lambda *a: True)


@pytest.fixture
def idp(world: World, monkeypatch: pytest.MonkeyPatch) -> FakeIdp:
    """Acme's IdP, matching the provider the ``world`` fixture configured for it."""
    fake = FakeIdp(issuer=world.sso_a.issuer, client_id="platform-a", client_secret="secret-a")
    monkeypatch.setattr(oidc, "http_json", fake.http_json)
    return fake


def start(slug: str = "acme") -> Any:
    return APIClient().get(f"/api/v1/auth/sso/{slug}/login/")


def sign_in(idp: FakeIdp, **behaviour: Any) -> dict[str, str]:
    """The whole browser round trip; returns the frontend redirect's query."""
    location = start()["Location"]
    callback = APIClient().get(CALLBACK, idp.authorize(location, **behaviour))
    assert callback.status_code == 302
    assert "eyJ" not in callback["Location"], "no token ever travels in a URL"
    return {k: v[0] for k, v in parse_qs(urlsplit(callback["Location"]).query).items()}


def failures() -> list[str]:
    return [e.metadata["reason"] for e in AuditLog.objects.filter(action=AuditAction.SSO_FAILED)]


# ---------------------------------------------------------------- the happy path
def test_a_member_signs_in_through_their_organizations_idp(world: World, idp: FakeIdp) -> None:
    result = sign_in(idp)
    assert set(result) == {"code"}
    tokens = APIClient().post(EXCHANGE, {"code": result["code"]})
    assert tokens.status_code == 200, tokens.content
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens.json()['access']}")
    assert client.get("/api/v1/auth/me/").json()["email"] == "admin@a.test"

    identity = SsoIdentity.objects.get()
    assert (identity.user, identity.subject) == (world.admin_a, "subject-alice")
    event = AuditLog.objects.get(action=AuditAction.LOGIN_SUCCEEDED)
    assert (event.actor, event.metadata) == (world.admin_a, {"channel": "sso"})
    # The one-time code is spent.
    assert APIClient().post(EXCHANGE, {"code": result["code"]}).status_code == 401


def test_the_authorize_redirect_carries_pkce_state_and_nonce(world: World, idp: FakeIdp) -> None:
    response = start()
    assert response.status_code == 302
    url = urlsplit(response["Location"])
    assert f"{url.scheme}://{url.netloc}{url.path}" == idp.discovery()["authorization_endpoint"]
    query = parse_qs(url.query)
    assert query["client_id"] == ["platform-a"]
    assert query["redirect_uri"] == ["http://localhost:8000/api/v1/auth/sso/callback/"]
    assert query["code_challenge_method"] == ["S256"]
    assert len(query["code_challenge"][0]) == 43  # base64url(SHA-256)
    assert len(query["state"][0]) >= 43
    assert len(query["nonce"][0]) >= 43
    assert query["state"] != query["nonce"]


def test_the_code_exchange_proves_possession_with_pkce(world: World, idp: FakeIdp) -> None:
    sign_in(idp)
    (exchange,) = idp.token_requests
    assert exchange["basic"] == ("platform-a", "secret-a"), "client authentication"
    assert exchange["form"]["grant_type"] == "authorization_code"
    assert len(exchange["form"]["code_verifier"]) >= 43
    # FakeIdp.token() refused anything whose S256(verifier) != challenge: it got through.


def test_a_linked_subject_keeps_signing_in_after_an_email_change(
    world: World, idp: FakeIdp
) -> None:
    sign_in(idp)
    result = sign_in(idp, claims={"email": "renamed@elsewhere.test"})
    assert APIClient().post(EXCHANGE, {"code": result["code"]}).status_code == 200


# ---------------------------------------------------------------- the ID token, attacked
@pytest.mark.parametrize(
    ("behaviour", "reason"),
    [
        ({"claims": {"iss": "https://evil.test/realms/a"}}, "invalid_id_token:InvalidIssuerError"),
        ({"claims": {"aud": "someone-else"}}, "invalid_id_token:InvalidAudienceError"),
        ({"claims": {"exp": int(time.time()) - 120}}, "invalid_id_token:ExpiredSignatureError"),
        ({"claims": {"iat": None}}, "invalid_id_token:MissingRequiredClaimError"),
        ({"claims": {"sub": None}}, "invalid_id_token:MissingRequiredClaimError"),
        ({"claims": {"nonce": "replayed-nonce"}}, "nonce_mismatch"),
        ({"claims": {"nonce": None}}, "nonce_mismatch"),
        ({"claims": {"aud": ["platform-a", "other"]}}, "azp_mismatch"),
        ({"signer": "none"}, "disallowed_algorithm"),
        ({"signer": "client-secret"}, "disallowed_algorithm"),
        (
            {"signer": rsa.generate_private_key(65537, 2048)},
            "invalid_id_token:InvalidSignatureError",
        ),
        ({"header": {"kid": "unknown"}}, "unknown_signing_key"),
        ({"claims": {"email_verified": False}}, "email_not_verified"),
        ({"claims": {"email_verified": "true"}}, "email_not_verified"),
    ],
    ids=[
        "wrong-issuer",
        "wrong-audience",
        "expired",
        "no-iat",
        "no-sub",
        "wrong-nonce",
        "no-nonce",
        "several-audiences-no-azp",
        "alg-none",
        "hs256-with-client-secret",
        "foreign-key",
        "unknown-kid",
        "email-not-verified",
        "email-verified-not-a-boolean",
    ],
)
def test_invalid_id_tokens_are_refused(
    world: World, idp: FakeIdp, behaviour: dict[str, Any], reason: str
) -> None:
    result = sign_in(idp, **behaviour)
    assert result == {"error": "sso_failed"}
    assert failures() == [reason]
    event = AuditLog.objects.get(action=AuditAction.SSO_FAILED)
    assert event.organization == world.org_a, "attributed to the tenant whose IdP it was"
    assert not SsoIdentity.objects.exists()


def test_several_audiences_are_fine_when_azp_is_us(world: World, idp: FakeIdp) -> None:
    result = sign_in(idp, claims={"aud": ["platform-a", "other"], "azp": "platform-a"})
    assert set(result) == {"code"}


def test_rotated_signing_keys_are_fetched_again(world: World, idp: FakeIdp) -> None:
    sign_in(idp)
    idp.key, idp.kid = rsa.generate_private_key(65537, 2048), "key-2"
    assert set(sign_in(idp)) == {"code"}
    assert idp.jwks_requests == 2


def test_a_discovery_document_for_another_issuer_is_refused(world: World, idp: FakeIdp) -> None:
    """Mix-up defence: the document must name exactly the issuer we trust."""
    idp.discovery_overrides = {"issuer": "https://idp.evil.test/"}
    assert start()["Location"].endswith("error=sso_unavailable")
    assert failures() == ["issuer_mismatch"]


def test_insecure_idp_endpoints_are_refused(world: World, idp: FakeIdp) -> None:
    idp.discovery_overrides = {"token_endpoint": "http://idp.a.test/token"}
    assert start()["Location"].endswith("error=sso_unavailable")
    assert failures() == ["insecure_idp_url"]


# ---------------------------------------------------------------- state, codes and replays
def test_state_is_single_use(world: World, idp: FakeIdp) -> None:
    params = idp.authorize(start()["Location"])
    first = APIClient().get(CALLBACK, params)
    assert "code=" in first["Location"]
    replay = APIClient().get(CALLBACK, params)
    assert replay["Location"].endswith("error=sso_failed")
    assert failures() == ["unknown_state"]


def test_an_unknown_state_is_refused(world: World, idp: FakeIdp) -> None:
    response = APIClient().get(CALLBACK, {"state": "forged", "code": "x"})
    assert response["Location"].endswith("error=sso_failed")
    event = AuditLog.objects.get(action=AuditAction.SSO_FAILED)
    assert event.organization is None  # nothing ties a forged state to a tenant


def test_an_idp_refusal_burns_the_state(world: World, idp: FakeIdp) -> None:
    params = idp.authorize(start()["Location"])
    refused = APIClient().get(CALLBACK, {"state": params["state"], "error": "access_denied"})
    assert refused["Location"].endswith("error=sso_failed")
    assert APIClient().get(CALLBACK, params)["Location"].endswith("error=sso_failed")
    assert sorted(failures()) == ["idp_refused", "unknown_state"]


def test_a_stolen_code_cannot_be_redeemed_without_the_verifier(world: World, idp: FakeIdp) -> None:
    """The authorization code alone, replayed at the token endpoint, is useless."""
    params = idp.authorize(start()["Location"])
    grant = idp.grants[params["code"]]
    with pytest.raises(oidc.SsoError):
        idp.token(
            {"code": params["code"], "code_verifier": "guess", "redirect_uri": grant.redirect_uri},
            ("platform-a", "secret-a"),
        )


def test_unknown_or_expired_exchange_codes_are_refused(world: World) -> None:
    response = APIClient().post(EXCHANGE, {"code": "never-issued"})
    assert response.status_code == 401
    assert "access" not in response.json()


# ---------------------------------------------------------------- tenants and members
def test_one_organizations_idp_cannot_sign_in_another_organizations_user(
    world: World, idp: FakeIdp
) -> None:
    """Acme's IdP vouches for admin@b.test (a Globex user): nobody is signed in."""
    assert sign_in(idp, claims={"email": "admin@b.test"}) == {"error": "sso_failed"}
    assert failures() == ["no_matching_member"]
    assert not SsoIdentity.objects.exists()


def test_the_idp_cannot_mint_super_admins(world: World, idp: FakeIdp) -> None:
    assert sign_in(idp, claims={"email": "root@platform.test"}) == {"error": "sso_failed"}


def test_unknown_people_are_not_provisioned(world: World, idp: FakeIdp) -> None:
    before = User.objects.count()
    assert sign_in(idp, claims={"email": "stranger@a.test"}) == {"error": "sso_failed"}
    assert User.objects.count() == before, "no just-in-time accounts: invitations only"


def test_allowed_domains_restrict_whom_the_idp_vouches_for(world: World, idp: FakeIdp) -> None:
    OidcProvider.objects.filter(pk=world.sso_a.pk).update(allowed_domains=["acme.test"])
    assert sign_in(idp) == {"error": "sso_failed"}
    assert failures() == ["email_domain_not_allowed"]


def test_a_linked_member_cannot_be_taken_over_by_another_subject(
    world: World, idp: FakeIdp
) -> None:
    sign_in(idp)
    hijack = sign_in(idp, claims={"sub": "subject-mallory"})
    assert hijack == {"error": "sso_failed"}
    assert failures() == ["member_linked_to_another_subject"]


def test_inactive_members_and_organizations_cannot_sign_in(world: World, idp: FakeIdp) -> None:
    assert sign_in(idp, claims={"email": "former@a.test"}) == {"error": "sso_failed"}
    Organization.objects.filter(pk=world.org_a.pk).update(is_active=False)
    assert start().status_code == 404


def test_unknown_organizations_and_organizations_without_sso_look_the_same(
    world: World, idp: FakeIdp
) -> None:
    OidcProvider.objects.filter(pk=world.sso_b.pk).delete()
    without_sso, unknown = start("globex"), start("no-such-org")
    assert without_sso.status_code == unknown.status_code == 404
    assert without_sso.json() == unknown.json()
    OidcProvider.objects.filter(pk=world.sso_a.pk).update(enabled=False)
    assert start("acme").status_code == 404


def test_an_unreachable_idp_sends_the_user_back_with_an_error(world: World, idp: FakeIdp) -> None:
    def down(url: str, **kwargs: Any) -> Any:
        raise oidc.SsoError("idp_unreachable")

    oidc.http_json = down  # restored by the idp fixture
    assert start()["Location"].endswith("error=sso_unavailable")


# ---------------------------------------------------------------- managing providers
PROVIDERS = "/api/v1/sso-providers/"


def test_an_org_admin_configures_their_provider(world: World, client_for: ClientFactory) -> None:
    OidcProvider.objects.filter(pk=world.sso_a.pk).delete()
    client = client_for(world.admin_a)
    response = client.post(
        PROVIDERS,
        {
            "issuer": "https://login.acme.test",
            "client_id": "platform",
            "client_secret": "s3cret-value",
            "allowed_domains": ["Acme.test", "acme.test"],
        },
        format="json",
    )
    assert response.status_code == 201, response.content
    body = response.json()
    assert "client_secret" not in body
    assert body["organization"] == str(world.org_a.pk)
    assert body["allowed_domains"] == ["acme.test"]
    assert body["login_url"] == "http://testserver/api/v1/auth/sso/acme/login/"
    provider = OidcProvider.objects.get(pk=body["id"])
    assert "s3cret-value" not in provider.client_secret_encrypted
    assert crypto.decrypt(provider.client_secret_encrypted) == "s3cret-value"
    event = AuditLog.objects.get(action=AuditAction.SSO_PROVIDER_CREATED)
    assert "s3cret-value" not in json.dumps(event.metadata)

    again = client.post(
        PROVIDERS,
        {"issuer": "https://x.acme.test", "client_id": "x", "client_secret": "y"},
        format="json",
    )
    assert again.status_code == 400, "one provider per organization"


def test_updating_the_secret_is_audited_by_name_only(
    world: World, client_for: ClientFactory
) -> None:
    url = reverse("ssoprovider-detail", args=[world.sso_a.pk])
    response = client_for(world.admin_a).patch(url, {"client_secret": "rotated-secret"})
    assert response.status_code == 200
    world.sso_a.refresh_from_db()
    assert crypto.decrypt(world.sso_a.client_secret_encrypted) == "rotated-secret"
    event = AuditLog.objects.get(action=AuditAction.SSO_PROVIDER_UPDATED)
    assert event.metadata == {"fields": ["client_secret"]}
    unchanged = client_for(world.admin_a).patch(url, {"enabled": True})
    assert unchanged.status_code == 200
    assert AuditLog.objects.filter(action=AuditAction.SSO_PROVIDER_UPDATED).count() == 1


@pytest.mark.parametrize(
    ("body", "field"),
    [
        ({"issuer": "http://login.acme.test"}, "issuer"),
        ({"issuer": "not a url"}, "issuer"),
        ({"allowed_domains": ["not a domain"]}, "allowed_domains"),
        ({"organization": "00000000-0000-0000-0000-000000000000"}, "organization"),
        ({"is_staff": True}, "is_staff"),
    ],
)
def test_provider_input_is_validated(
    world: World, client_for: ClientFactory, body: dict[str, Any], field: str
) -> None:
    url = reverse("ssoprovider-detail", args=[world.sso_a.pk])
    response = client_for(world.admin_a).patch(url, body, format="json")
    assert response.status_code == 400
    assert field in response.json()


def test_an_org_admin_cannot_configure_another_tenants_sso(
    world: World, client_for: ClientFactory
) -> None:
    OidcProvider.objects.filter(pk=world.sso_b.pk).delete()
    response = client_for(world.admin_a).post(
        PROVIDERS,
        {
            "issuer": "https://evil.test",
            "client_id": "x",
            "client_secret": "y",
            "organization": str(world.org_b.pk),
        },
        format="json",
    )
    assert response.status_code == 400
    assert "does not exist" in str(response.json()["organization"])
    assert not OidcProvider.objects.filter(organization=world.org_b).exists()


def test_super_admins_configure_any_tenant(world: World, client_for: ClientFactory) -> None:
    OidcProvider.objects.filter(pk=world.sso_b.pk).delete()
    client = client_for(world.super_admin)
    body = {"issuer": "https://login.globex.test", "client_id": "x", "client_secret": "y"}
    assert client.post(PROVIDERS, body, format="json").status_code == 400, "whose? say so"
    created = client.post(PROVIDERS, {**body, "organization": str(world.org_b.pk)}, format="json")
    assert created.status_code == 201
    assert created.json()["organization"] == str(world.org_b.pk)


def test_creating_needs_a_secret_and_the_organization_is_immutable(
    world: World, client_for: ClientFactory
) -> None:
    OidcProvider.objects.filter(pk=world.sso_a.pk).delete()
    client = client_for(world.admin_a)
    missing = client.post(PROVIDERS, {"issuer": "https://a.test", "client_id": "x"})
    assert "client_secret" in missing.json()
    created = client.post(
        PROVIDERS, {"issuer": "https://a.test", "client_id": "x", "client_secret": "y"}
    ).json()
    moved = client_for(world.super_admin).patch(
        reverse("ssoprovider-detail", args=[created["id"]]), {"organization": str(world.org_b.pk)}
    )
    assert moved.status_code == 400


def test_removing_a_provider(world: World, client_for: ClientFactory) -> None:
    url = reverse("ssoprovider-detail", args=[world.sso_a.pk])
    assert client_for(world.admin_a).delete(url).status_code == 204
    assert not OidcProvider.objects.filter(pk=world.sso_a.pk).exists()
    assert AuditLog.objects.filter(action=AuditAction.SSO_PROVIDER_DELETED).count() == 1


# ---------------------------------------------------------------- the HTTP client itself
class _IdpHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/slow":
            time.sleep(2)
        if self.path == "/broken":
            self.send_response(500)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        body = b"not json" if self.path == "/garbage" else json.dumps({"ok": True}).encode()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers["Content-Length"])
        echo = {
            "form": self.rfile.read(length).decode(),
            "authorization": self.headers.get("Authorization"),
        }
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(echo).encode())

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def local_idp() -> Iterator[str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _IdpHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@override_settings(SSO_ALLOW_HTTP=True, SSO_HTTP_TIMEOUT_SECONDS=0.5)
def test_the_idp_http_client(local_idp: str) -> None:
    assert oidc.http_json(f"{local_idp}/ok") == {"ok": True}
    echo = oidc.http_json(f"{local_idp}/token", form={"code": "a b"}, basic=("id", "s:cret"))
    assert echo["form"] == "code=a+b"
    assert echo["authorization"] == "Basic aWQ6cyUzQWNyZXQ="  # form-encoded, then base64
    for path, reason in (
        ("/broken", "idp_error"),
        ("/garbage", "idp_unreachable"),
        ("/slow", "idp_unreachable"),
    ):
        with pytest.raises(oidc.SsoError) as caught:
            oidc.http_json(f"{local_idp}{path}")
        assert caught.value.reason == reason


def test_plain_http_idps_are_refused_by_default(local_idp: str) -> None:
    with pytest.raises(oidc.SsoError, match="insecure_idp_url"):
        oidc.http_json(f"{local_idp}/ok")


# ---------------------------------------------------------------- malformed IdP answers
@pytest.mark.parametrize(
    ("document", "reason"),
    [(["not", "an", "object"], "bad_discovery"), ({"issuer": "SAME"}, "bad_discovery")],
    ids=["not-an-object", "missing-endpoints"],
)
def test_malformed_discovery_documents_are_refused(
    world: World, monkeypatch: pytest.MonkeyPatch, document: Any, reason: str
) -> None:
    if isinstance(document, dict):
        document = {"issuer": world.sso_a.issuer}
    monkeypatch.setattr(oidc, "http_json", lambda url, **kw: document)
    with pytest.raises(oidc.SsoError) as caught:
        oidc.discover(world.sso_a.issuer)
    assert caught.value.reason == reason


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        ({"token_type": "Bearer"}, "no_id_token"),
        ({"id_token": "not.a.jwt"}, "malformed_id_token"),
        ("jwks-garbage", "bad_jwks"),
    ],
)
def test_malformed_token_answers_are_refused(
    world: World, idp: FakeIdp, monkeypatch: pytest.MonkeyPatch, answer: Any, reason: str
) -> None:
    real = idp.http_json

    def tampered(url: str, **kwargs: Any) -> Any:
        if answer == "jwks-garbage" and url.endswith("/certs"):
            return {"keys": "garbage"}
        if isinstance(answer, dict) and kwargs.get("form"):
            real(url, **kwargs)  # the IdP still checks the request
            return answer
        return real(url, **kwargs)

    monkeypatch.setattr(oidc, "http_json", tampered)
    assert sign_in(idp) == {"error": "sso_failed"}
    assert failures() == [reason]


def test_a_provider_disabled_mid_flow_is_refused(world: World, idp: FakeIdp) -> None:
    params = idp.authorize(start()["Location"])
    OidcProvider.objects.filter(pk=world.sso_a.pk).update(enabled=False)
    assert APIClient().get(CALLBACK, params)["Location"].endswith("error=sso_failed")
    assert failures() == ["provider_gone"]


def test_a_member_deactivated_after_the_callback_cannot_exchange(
    world: World, idp: FakeIdp
) -> None:
    code = sign_in(idp)["code"]
    User.objects.filter(pk=world.admin_a.pk).update(is_active=False)
    assert APIClient().post(EXCHANGE, {"code": code}).status_code == 401


def test_sso_models_describe_themselves(world: World, idp: FakeIdp) -> None:
    sign_in(idp)
    assert str(world.sso_a).startswith("https://idp.a.test/realms/a for ")
    assert str(SsoIdentity.objects.get()) == f"subject-alice -> {world.admin_a.pk}"
