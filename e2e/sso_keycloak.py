"""End-to-end SSO against a real Keycloak (docker compose --profile sso).

Runs inside the compose network, where the API is http://api:8000 and Keycloak
is http://keycloak:8080, so the issuer URL is the same for the browser leg
(played here) and for the API's back channel. Standard library only.

    docker compose --profile sso up -d --build --wait
    docker compose exec api python manage.py seed_demo --force
    docker compose --profile sso run --rm sso-e2e

Checks: Alice signs in through Acme's IdP and gets a session; replaying the
callback fails; Bob (email not verified at the IdP) is refused; Grace (a
Globex user) cannot be signed in through Acme's IdP.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Any

API = os.environ.get("API_URL", "http://api:8000")
KEYCLOAK = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
ISSUER = f"{KEYCLOAK}/realms/acme"
CLIENT_ID = "secure-multi-tenant-platform"
CLIENT_SECRET = "local-keycloak-client-secret-not-for-production"  # noqa: S105 - local realm
DEMO_PASSWORD = "Demo-Passw0rd!2026"  # noqa: S105 - seed_demo
IDP_PASSWORD = "Keycloak-Passw0rd!"  # noqa: S105 - local realm
TIMEOUT = 15


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # surface every 3xx to the caller


def browser() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), _NoRedirects()
    )


def call(
    opener: urllib.request.OpenerDirector,
    method: str,
    url: str,
    *,
    form: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    token: str | None = None,
) -> tuple[int, dict[str, str], str]:
    headers = {"Accept": "application/json, text/html"}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)  # noqa: S310
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            return response.status, dict(response.headers), response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode(errors="replace")


class _LoginForm(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.action: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form" and values.get("id") == "kc-form-login":
            self.action = values.get("action")


def check(condition: bool, message: str) -> None:
    print(("PASS " if condition else "FAIL ") + message)
    if not condition:
        sys.exit(1)


def api_login(email: str) -> str:
    status, _, text = call(
        browser(),
        "POST",
        f"{API}/api/v1/auth/login/",
        body={"email": email, "password": DEMO_PASSWORD},
    )
    check(status == 200, f"{email} signs in with a password ({status})")
    return str(json.loads(text)["access"])


def configure_provider(admin_token: str) -> None:
    opener = browser()
    status, _, text = call(opener, "GET", f"{API}/api/v1/sso-providers/", token=admin_token)
    existing = json.loads(text)["results"]
    payload = {"issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}
    if existing:
        url = f"{API}/api/v1/sso-providers/{existing[0]['id']}/"
        status, _, text = call(opener, "PATCH", url, body=payload, token=admin_token)
    else:
        status, _, text = call(
            opener, "POST", f"{API}/api/v1/sso-providers/", body=payload, token=admin_token
        )
    check(status in {200, 201}, f"Alice configures Acme's OIDC provider ({status} {text[:200]})")


def sso_round_trip(username: str) -> tuple[dict[str, str], str]:
    """Play the browser: API -> Keycloak login form -> callback -> frontend redirect."""
    opener = browser()
    status, headers, _ = call(opener, "GET", f"{API}/api/v1/auth/sso/acme/login/")
    check(status == 302, f"[{username}] the API redirects to the IdP ({status})")
    authorize = headers["Location"]
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(authorize).query)
    check(query.get("code_challenge_method") == ["S256"], f"[{username}] PKCE S256 is requested")
    check(bool(query.get("state")) and bool(query.get("nonce")), f"[{username}] state and nonce")

    status, _, page = call(opener, "GET", authorize)
    form = _LoginForm()
    form.feed(page)
    check(status == 200 and form.action is not None, f"[{username}] Keycloak shows its login form")
    status, headers, _ = call(
        opener, "POST", str(form.action), form={"username": username, "password": IDP_PASSWORD}
    )
    check(status == 302, f"[{username}] Keycloak accepts the credentials ({status})")
    callback = headers["Location"]
    check(callback.startswith(f"{API}/api/v1/auth/sso/callback/"), f"[{username}] back to the API")

    status, headers, _ = call(opener, "GET", callback)
    check(status == 302, f"[{username}] the callback redirects to the frontend ({status})")
    final = headers["Location"]
    check("eyJ" not in final, f"[{username}] no token in the redirect URL")
    params = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(final).query).items()}
    return params, callback


def main() -> None:
    admin_token = api_login("alice@acme.test")
    configure_provider(admin_token)

    params, callback = sso_round_trip("alice")
    check(set(params) == {"code"}, "Alice gets a one-time code")
    status, _, text = call(browser(), "POST", f"{API}/api/v1/auth/sso/exchange/", body=params)
    check(status == 200, f"the code is exchanged for a token pair ({status})")
    tokens = json.loads(text)
    status, _, text = call(browser(), "GET", f"{API}/api/v1/auth/me/", token=tokens["access"])
    check(
        status == 200 and json.loads(text)["email"] == "alice@acme.test", "the session is Alice's"
    )
    status, _, _ = call(browser(), "POST", f"{API}/api/v1/auth/sso/exchange/", body=params)
    check(status == 401, f"the one-time code works once ({status})")

    status, headers, _ = call(browser(), "GET", callback)
    check(headers.get("Location", "").endswith("error=sso_failed"), "replaying the callback fails")

    params, _ = sso_round_trip("bob")
    check(params == {"error": "sso_failed"}, "Bob (email not verified at the IdP) is refused")
    params, _ = sso_round_trip("grace")
    check(params == {"error": "sso_failed"}, "Grace (Globex) cannot sign in through Acme's IdP")
    print("SSO end-to-end: all checks passed")


if __name__ == "__main__":
    main()
