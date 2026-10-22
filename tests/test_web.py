"""The public landing page, the themed API docs and the Content Security Policy."""

from __future__ import annotations

import gzip
import re
from collections import Counter
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.test import Client, RequestFactory, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from apps.accounts.authentication import TenantJWTAuthentication
from apps.accounts.models import User
from apps.accounts.roles import ROLE_PERMISSIONS, Perm
from apps.accounts.views.users import UserViewSet
from apps.auditlogs.models import AuditAction
from apps.common.context import RequestContext, bind_request_context, reset_request_context
from apps.common.permissions import HasRolePermission, TenantObjectPermission
from apps.common.tenancy import TenantQuerySet
from apps.web import errors
from apps.web import views as web_views
from apps.web.content import TEST_SUITE
from apps.web.views import PERMISSION_LABELS, Quantity, humanize_duration, humanize_rate
from tests.conftest import ClientFactory, World

HTML_PAGES = ("/", "/api/docs/", "/api/redoc/")
STATIC_DIR = Path(__file__).resolve().parent.parent / "apps" / "web" / "static" / "web"
ERROR_PAGE = "/no-such-page/"


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
@pytest.mark.parametrize("url", [*HTML_PAGES, ERROR_PAGE])
def test_pages_need_no_inline_code_or_third_party_assets(api_client: APIClient, url: str) -> None:
    html = api_client.get(url).content.decode()

    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), "inline script"
    assert "<style" not in html, "inline style element"
    assert not re.search(r"\sstyle=", html), "inline style attribute"
    # Every script, stylesheet, font and icon is served by this app.
    for tag in re.findall(r"<(?:script|link)\b[^>]*>", html):
        assert not re.search(r"(?:src|href)=\"(?:https?:)?//", tag), tag


@pytest.mark.django_db
@pytest.mark.parametrize("url", [*HTML_PAGES, ERROR_PAGE, "/api/v1/auth/me/", "/health/live/"])
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


@pytest.mark.django_db
def test_swagger_keeps_deep_links_with_the_accessibility_plugin(api_client: APIClient) -> None:
    spectacular = cast(dict[str, Any], settings.SPECTACULAR_SETTINGS)
    assert spectacular["SWAGGER_UI_SETTINGS"]["deepLinking"] is True
    page = api_client.get("/api/docs/").content.decode()
    scripts = re.findall(r'<script src="([^"]+)"', page)
    # The plugin wraps SwaggerUIBundle, so it must load after it and before the init script.
    bundle = next(i for i, src in enumerate(scripts) if "swagger-ui-bundle" in src)
    plugin = scripts.index("/static/web/js/swagger-plugins.js")
    init = next(i for i, src in enumerate(scripts) if "script" in src.split("?", 1)[-1])
    assert bundle < plugin < init


@pytest.mark.django_db
def test_redoc_runs_a_self_hosted_bundle_that_makes_no_third_party_requests(
    api_client: APIClient,
) -> None:
    page = api_client.get("/api/redoc/").content.decode()
    src = re.search(r'<script src="(/api/redoc/redoc\.standalone\.js\?v=[0-9a-f]{16})"', page)
    assert src, "the page must load the patched bundle"

    response = api_client.get(src.group(1), HTTP_ACCEPT_ENCODING="gzip")
    assert response.status_code == 200
    assert response["Content-Type"].startswith("text/javascript")
    assert response["Content-Encoding"] == "gzip"
    assert "immutable" in response["Cache-Control"]
    bundle = gzip.decompress(response.content).decode()
    assert "cdn.redoc.ly" not in bundle
    assert '"/static/web/vendor/redoc/logo-mini.svg"' in bundle
    assert "#0e7c86" not in bundle, "the low-contrast pattern colour"
    assert ".h5`" not in bundle, "section labels that skip heading levels"
    assert api_client.get(src.group(1)).content == bundle.encode()

    cached = api_client.get(src.group(1), HTTP_IF_NONE_MATCH=response["ETag"])
    assert cached.status_code == 304


def test_redoc_patches_fail_loudly_when_the_bundle_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stale = (web_views._Patch("not in the bundle", lambda: "", "test"),)
    monkeypatch.setattr(web_views, "REDOC_PATCHES", stale)
    web_views.self_hosted_redoc_bundle.cache_clear()
    try:
        with pytest.raises(ImproperlyConfigured, match="Redoc bundle changed"):
            web_views.self_hosted_redoc_bundle()
    finally:
        monkeypatch.undo()
        web_views.self_hosted_redoc_bundle.cache_clear()


# ---------------------------------------------------------------- error pages
@pytest.mark.django_db
def test_unknown_pages_get_the_branded_404(api_client: APIClient) -> None:
    response = api_client.get(ERROR_PAGE)
    assert response.status_code == 404
    assert response["Content-Type"].startswith("text/html")
    html = response.content.decode()
    assert "Error 404" in html
    assert errors.ERRORS[404].title in html
    assert 'href="/"' in html


@pytest.mark.django_db
def test_unknown_api_routes_answer_like_the_api(api_client: APIClient) -> None:
    response = api_client.get("/api/v1/no-such-endpoint/")
    assert response.status_code == 404
    assert response.json() == {"detail": "Not found."}


@pytest.mark.parametrize(
    ("path", "json"), [("/somewhere/", False), ("/api/v1/users/", True)], ids=["page", "api"]
)
def test_server_errors_are_branded_and_carry_the_request_id(path: str, json: bool) -> None:
    request = RequestFactory().get(path)
    token = bind_request_context(RequestContext("req-boom-0001", None, ""))
    try:
        response = errors.server_error(request)
    finally:
        reset_request_context(token)

    assert response.status_code == 500
    body = response.content.decode()
    if json:
        assert response["Content-Type"] == "application/json"
        assert body == '{"detail": "A server error occurred."}'
    else:
        assert errors.ERRORS[500].title in body
        assert "<code>req-boom-0001</code>" in body
        assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>|<style|\sstyle=", body)


@pytest.mark.django_db
def test_csrf_failures_get_a_page_the_csp_allows() -> None:
    """Django's own CSRF page relies on an inline <style> that the policy blocks."""
    response = Client(enforce_csrf_checks=True).post("/admin/login/", {"username": "x"})
    assert response.status_code == 403
    html = response.content.decode()
    assert "Error 403" in html
    assert "<style" not in html


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


@pytest.mark.django_db
def test_landing_is_compressed_for_clients_that_accept_it(api_client: APIClient) -> None:
    response = api_client.get("/", HTTP_ACCEPT_ENCODING="gzip")

    assert response["Content-Encoding"] == "gzip"
    assert "Accept-Encoding" in response["Vary"]
    html = gzip.decompress(response.content).decode()
    assert html.startswith("<!doctype html>")
    assert html.rstrip().endswith("</html>")
    assert "Not forbidden. Absent." in html
    # Nothing secret or request-reflected rides along for a compression oracle.
    assert "csrfmiddlewaretoken" not in html
    assert "csrftoken" not in response.cookies


# ---------------------------------------------------------------- isolation story
STORY_STEPS = (
    ("Request", "Alice asks for Grace."),
    ("Tenant resolve", "The tenant comes from the database."),
    ("Scoped query", "Only Acme&rsquo;s rows exist."),
    ("404", "Not forbidden. Absent."),
)


def _story(html: str) -> str:
    start = html.index('<div class="story" data-story>')
    return html[start : html.index("</ol>", start)]


@pytest.mark.django_db
def test_landing_tells_the_isolation_story_without_javascript(api_client: APIClient) -> None:
    """Every step and the finished figure are server-rendered; motion only builds them up."""
    story = _story(api_client.get("/").content.decode())

    for kicker, title in STORY_STEPS:
        assert f"</span>{kicker}</p>" in story
        assert f'<h3 class="t-tile">{title}</h3>' in story
    assert story.count('class="story-step"') == len(STORY_STEPS)
    assert story.count('class="story-mark" aria-hidden="true"') == len(STORY_STEPS)
    for label in (
        "/api/v1/users/{grace&rsquo;s id}/",
        "TenantJWTAuthentication",
        "Acme Corp",
        "Globex Inc",
        "visible_to(alice)",
        "WHERE organization_id = {acme&rsquo;s id}",
        "AND id = {grace&rsquo;s id}",
        "0 rows",
        "404 Not Found",
        "Same as a random ID",
    ):
        assert label in story, label
    # Nothing in the story starts hidden: no hidden attribute, no inline style.
    assert not re.search(r"\shidden\b|\sstyle=", story)


@pytest.mark.django_db
def test_the_story_shows_what_the_api_really_does(
    api_client: APIClient, world: World, client_for: ClientFactory
) -> None:
    """The figure's 404 body, SQL and code names are the real ones, not illustrations."""
    story = _story(api_client.get("/").content.decode())

    foreign = client_for(world.admin_a).get(reverse("user-detail", args=[world.admin_b.pk]))
    assert foreign.status_code == 404
    assert f'{{"detail": "{foreign.json()["detail"]}"}}' in story

    scoped = User.objects.visible_to(world.admin_a).filter(pk=world.admin_b.pk)
    where = str(scoped.query).split(" WHERE ", 1)[1]
    assert f'"accounts_user"."organization_id" = {world.org_a.pk.hex}' in where.replace("-", "")
    assert '"accounts_user"."id" =' in where
    assert not scoped.exists()

    assert "get_user" in vars(TenantJWTAuthentication)
    assert isinstance(User.objects.all(), TenantQuerySet)
    assert "visible_to" in vars(TenantQuerySet)
    for name in ("UserViewSet", "TenantJWTAuthentication.get_user", "TenantQuerySet.visible_to"):
        assert f"<code>{name}</code>" in story
    guards = {type(permission) for permission in UserViewSet().get_permissions()}
    assert {HasRolePermission, TenantObjectPermission} <= guards
    isolation_tests = (Path(__file__).parent / "test_tenant_isolation.py").read_text()
    assert "def test_unknown_and_foreign_ids_are_indistinguishable(" in isolation_tests


def _blocks(css: str, prelude: str) -> list[str]:
    """The bodies of every top-level block whose prelude starts with ``prelude``."""
    bodies, start = [], 0
    while (at := css.find(prelude, start)) != -1:
        depth, i = 0, css.index("{", at)
        for j in range(i, len(css)):
            depth += {"{": 1, "}": -1}.get(css[j], 0)
            if depth == 0:
                bodies.append(css[i + 1 : j])
                break
        start = j
    return bodies


def test_scroll_motion_only_exists_without_reduced_motion() -> None:
    """With reduced motion, or without scroll timelines and the script, the story is static."""
    css = (STATIC_DIR / "css" / "site.css").read_text()
    motion = "".join(_blocks(css, "@media (prefers-reduced-motion: no-preference)"))
    outside = css
    for body in _blocks(css, "@media (prefers-reduced-motion: no-preference)"):
        outside = outside.replace(body, "")

    for token in ("animation-timeline", "view-timeline", "js-scrub", "sx-in", "sx-draw"):
        assert token in motion, token
    for token in ("animation-timeline", "view-timeline", "js-scrub", "animation:"):
        assert token not in outside.split("@keyframes", 1)[0], token
    # Native scroll timelines only apply where the browser has them.
    native = "".join(_blocks(motion, "@supports (animation-timeline: view()) and (timeline-scope"))
    assert native.count("animation-timeline: --s") == motion.count("animation-timeline: --s") > 0


def test_story_script_only_hides_what_it_has_already_placed() -> None:
    script = (STATIC_DIR / "js" / "story.js").read_text()

    assert "prefers-reduced-motion: reduce" in script
    # The fallback class is added only after the first progress values are set.
    apply = script[script.index("const apply") :]
    assert apply.index("update();") < apply.index('classList.add("js-scrub")')
    # No eval-like constructs or HTML injection (strict CSP, no unsafe-eval).
    assert not re.search(r"\beval\(|new Function|innerHTML|setAttribute\(\"style", script)


@pytest.mark.django_db
def test_story_script_is_served_same_origin_with_safe_headers(api_client: APIClient) -> None:
    html = api_client.get("/").content.decode()
    assert '<script src="/static/web/js/story.js" defer></script>' in html

    with override_settings(WHITENOISE_USE_FINDERS=True, WHITENOISE_AUTOREFRESH=True):
        response = Client().get("/static/web/js/story.js")

    assert response.status_code == 200
    assert response["Content-Type"].startswith("text/javascript")
    assert response["X-Content-Type-Options"] == "nosniff"
    assert "script-src 'self'" in response["Content-Security-Policy"]
    body = b"".join(cast(Any, response).streaming_content).decode()
    assert body == (STATIC_DIR / "js" / "story.js").read_text()
