"""The public landing page, the themed API docs and the Content Security Policy."""

from __future__ import annotations

import re
from collections import Counter
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from rest_framework.test import APIClient

from apps.accounts.roles import ROLE_PERMISSIONS, Perm
from apps.auditlogs.models import AuditAction
from apps.web.content import TEST_SUITE
from apps.web.views import PERMISSION_LABELS, Quantity, humanize_duration, humanize_rate

HTML_PAGES = ("/", "/api/docs/", "/api/redoc/")


@pytest.mark.django_db
def test_landing_renders_facts_from_code_and_settings(api_client: APIClient) -> None:
    response = api_client.get("/")
    html = response.content.decode()

    assert response.status_code == 200
    assert response["Content-Type"].startswith("text/html")
    assert "Every tenant." in html
    assert "This server is ready" in html
    # The role matrix is generated from ROLE_PERMISSIONS, cell for cell.
    granted = sum(len(perms) for perms in ROLE_PERMISSIONS.values())
    assert html.count(">Granted<") == granted
    assert html.count(">Not granted<") == len(ROLE_PERMISSIONS) * len(Perm) - granted
    for action in AuditAction:
        assert f"<li>{action.value}</li>" in html
    # Token lifetime and throttle come from settings (5 minutes, 10/min by default).
    assert re.search(r"<b>5</b><span>minutes</span>", html)
    assert re.search(r"<b>10</b><span>per minute</span>", html)


@pytest.mark.django_db
def test_landing_reports_a_degraded_dependency(
    api_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: Any, **kwargs: Any) -> None:
        raise ConnectionError("down")

    monkeypatch.setattr("apps.common.views.cache.set", boom)
    response = api_client.get("/")

    assert response.status_code == 200, "the page itself must not fail with its dependencies"
    html = response.content.decode()
    assert 'data-ready="false"' in html
    assert "This server is degraded" in html


@pytest.mark.django_db
@pytest.mark.parametrize("url", HTML_PAGES)
def test_pages_need_no_inline_code_or_third_party_assets(api_client: APIClient, url: str) -> None:
    html = api_client.get(url).content.decode()

    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), "inline script"
    assert "<style" not in html, "inline style element"
    assert not re.search(r"\sstyle=", html), "inline style attribute"
    # Every script, stylesheet, font and icon is served by this app.
    for tag in re.findall(r"<(?:script|link)\b[^>]*>", html):
        assert not re.search(r"(?:src|href)=\"(?:https?:)?//", tag), tag


@pytest.mark.django_db
@pytest.mark.parametrize("url", [*HTML_PAGES, "/api/v1/auth/me/", "/health/live/"])
def test_strict_content_security_policy_on_every_response(api_client: APIClient, url: str) -> None:
    policy = api_client.get(url)["Content-Security-Policy"]
    directives = {
        name: values
        for name, _, values in (part.strip().partition(" ") for part in policy.split(";"))
    }

    assert directives["default-src"] == "'self'"
    assert directives["script-src"] == "'self'"
    assert directives["object-src"] == "'none'"
    assert directives["base-uri"] == "'none'"
    assert directives["frame-ancestors"] == "'none'"
    assert "unsafe-eval" not in policy
    assert "unsafe-inline" not in policy


@pytest.mark.django_db
def test_swagger_init_script_is_served_separately(api_client: APIClient) -> None:
    page = api_client.get("/api/docs/").content.decode()
    script_url = re.search(r'<script src="(/api/docs/\?[^"]*script[^"]*)"', page)
    assert script_url, "the init script must be an external, same-origin file"

    script = api_client.get(script_url.group(1).replace("&amp;", "&"))

    assert script.status_code == 200
    assert script["Content-Type"].startswith("application/javascript")
    assert "SwaggerUIBundle(" in script.content.decode()


@pytest.mark.parametrize(
    ("delta", "expected"),
    [
        (timedelta(minutes=5), Quantity(5, "minutes")),
        (timedelta(days=1), Quantity(1, "day")),
        (timedelta(hours=72), Quantity(3, "days")),
        (timedelta(minutes=90), Quantity(90, "minutes")),
        (timedelta(seconds=45), Quantity(45, "seconds")),
    ],
)
def test_durations_are_shown_in_their_largest_exact_unit(
    delta: timedelta, expected: Quantity
) -> None:
    assert humanize_duration(delta) == expected


def test_throttle_rates_are_humanized() -> None:
    assert humanize_rate("10/min") == Quantity(10, "per minute")
    assert humanize_rate("600/hour") == Quantity(600, "per hour")


def test_every_permission_has_a_label() -> None:
    assert set(PERMISSION_LABELS) == set(Perm)


def test_landing_test_inventory_matches_the_suite(request: pytest.FixtureRequest) -> None:
    """The per-file counts on the landing page are the real ones."""
    options = request.config.option
    collected = Counter(Path(str(item.path)).name for item in request.session.items)
    every_file = {path.name for path in Path(__file__).parent.glob("test_*.py")}
    if set(collected) != every_file or options.keyword or options.markexpr:
        pytest.skip("Only meaningful when the whole suite is collected.")

    assert dict(collected) == {entry.path: entry.tests for entry in TEST_SUITE}
