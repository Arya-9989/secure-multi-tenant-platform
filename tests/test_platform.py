"""Operational concerns: health probes, API docs, request IDs, logging, settings."""

from __future__ import annotations

import io
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import RequestFactory, override_settings
from rest_framework.test import APIClient

from apps.accounts.models import User
from apps.accounts.roles import Role
from apps.common.context import RequestContext, bind_request_context, reset_request_context
from apps.common.logging import JsonFormatter, RequestContextFilter
from apps.common.net import get_client_ip
from apps.organizations.models import Organization

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------- health
@pytest.mark.django_db
def test_liveness_and_readiness(api_client: APIClient) -> None:
    assert api_client.get("/health/live/").json() == {"status": "ok"}
    ready = api_client.get("/health/ready/")
    assert ready.status_code == 200
    assert ready.json() == {"status": "ok", "checks": {"database": "ok", "cache": "ok"}}


@pytest.mark.django_db
@pytest.mark.parametrize("broken", ["database", "cache"])
def test_readiness_reports_failing_dependency(
    api_client: APIClient, monkeypatch: pytest.MonkeyPatch, broken: str
) -> None:
    def boom(*args: Any, **kwargs: Any) -> None:
        raise ConnectionError("down")

    if broken == "database":
        monkeypatch.setattr("apps.common.views.connection.cursor", boom)
    else:
        monkeypatch.setattr("apps.common.views.cache.set", boom)
    response = api_client.get("/health/ready/")
    assert response.status_code == 503
    assert response.json()["checks"][broken] == "error"


@pytest.mark.django_db
def test_readiness_detects_cache_returning_wrong_value(
    api_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("apps.common.views.cache.get", lambda *a, **k: None)
    assert api_client.get("/health/ready/").status_code == 503


# ---------------------------------------------------------------- API docs
def test_openapi_schema_has_no_warnings_and_is_valid() -> None:
    call_command("spectacular", "--fail-on-warn", "--validate", "--file", os.devnull)


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("url", "marker"),
    [("/api/docs/", "swagger-ui"), ("/api/redoc/", "redoc"), ("/api/schema/", "openapi")],
)
def test_docs_are_served(api_client: APIClient, url: str, marker: str) -> None:
    response = api_client.get(url)
    assert response.status_code == 200
    assert marker in response.content.decode().lower()


@pytest.mark.django_db
def test_root_redirects_to_docs(api_client: APIClient) -> None:
    response = api_client.get("/")
    assert response.status_code == 302
    assert response["Location"] == "/api/docs/"


# ---------------------------------------------------------------- request context
@pytest.mark.django_db
def test_request_id_is_propagated_or_generated(api_client: APIClient) -> None:
    echoed = api_client.get("/health/live/", HTTP_X_REQUEST_ID="lb-0123456789")
    assert echoed["X-Request-ID"] == "lb-0123456789"
    generated = api_client.get("/health/live/", HTTP_X_REQUEST_ID="bad id\nInjected: yes")
    assert len(generated["X-Request-ID"]) == 32
    assert "\n" not in generated["X-Request-ID"]


@pytest.mark.django_db
def test_security_headers(api_client: APIClient) -> None:
    response = api_client.get("/health/live/")
    assert response["X-Frame-Options"] == "DENY"
    assert response["X-Content-Type-Options"] == "nosniff"
    assert response["Referrer-Policy"] == "same-origin"


@pytest.mark.parametrize(
    ("num_proxies", "remote", "forwarded", "expected"),
    [
        (0, "10.0.0.1", "6.6.6.6", "10.0.0.1"),  # header ignored without trusted proxies
        (1, "10.0.0.1", "6.6.6.6, 198.51.100.4", "198.51.100.4"),  # spoofed prefix ignored
        (2, "10.0.0.1", "198.51.100.4, 10.0.0.9", "198.51.100.4"),
        (1, "10.0.0.1", "", "10.0.0.1"),
        (1, "10.0.0.1", "not-an-ip", None),
    ],
)
def test_client_ip_trusts_only_configured_proxies(
    num_proxies: int, remote: str, forwarded: str, expected: str | None
) -> None:
    request = RequestFactory().get("/", REMOTE_ADDR=remote, HTTP_X_FORWARDED_FOR=forwarded)
    with override_settings(NUM_PROXIES=num_proxies):
        assert get_client_ip(request) == expected


# ---------------------------------------------------------------- logging
def test_json_formatter_includes_request_id_and_extras() -> None:
    record = logging.LogRecord("apps.test", logging.INFO, __file__, 1, "hello %s", ("world",), None)
    record.status_code = 201
    token = bind_request_context(RequestContext("req-42", "127.0.0.1", "ua"))
    try:
        RequestContextFilter().filter(record)
    finally:
        reset_request_context(token)
    payload = json.loads(JsonFormatter().format(record))
    assert payload["message"] == "hello world"
    assert payload["request_id"] == "req-42"
    assert payload["status_code"] == 201
    assert payload["level"] == "INFO"


def test_json_formatter_serializes_exceptions() -> None:
    try:
        raise ValueError("kaboom")
    except ValueError:
        record = logging.LogRecord(
            "apps.test", logging.ERROR, __file__, 1, "failed", (), sys.exc_info()
        )
    RequestContextFilter().filter(record)
    payload = json.loads(JsonFormatter().format(record))
    assert payload["request_id"] == "-"
    assert "ValueError: kaboom" in payload["exc_info"]


@pytest.mark.django_db
def test_access_log_line_is_emitted(
    api_client: APIClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="apps.access"):
        api_client.get("/api/v1/users/")
    (entry,) = [r for r in caplog.records if r.name == "apps.access"]
    assert entry.status_code == 401  # type: ignore[attr-defined]
    assert entry.path == "/api/v1/users/"  # type: ignore[attr-defined]


# ---------------------------------------------------------------- settings safety
def _import_settings(**env: str) -> subprocess.CompletedProcess[str]:
    clean = {k: v for k, v in os.environ.items() if not k.startswith(("DJANGO_", "JWT_"))}
    return subprocess.run(
        [sys.executable, "-c", "import config.settings"],
        cwd=ROOT,
        env={**clean, "DJANGO_SECRET_KEY": "", **env},
        capture_output=True,
        text=True,
        check=False,
    )


def test_production_settings_refuse_to_start_without_a_secret() -> None:
    result = _import_settings(DJANGO_DEBUG="False")
    assert result.returncode != 0
    assert "DJANGO_SECRET_KEY must be set" in result.stderr


def test_production_settings_refuse_a_short_jwt_key() -> None:
    result = _import_settings(DJANGO_SECRET_KEY="x" * 50, JWT_SIGNING_KEY="short")
    assert result.returncode != 0
    assert "at least 32 characters" in result.stderr


def test_debug_settings_start_without_a_secret() -> None:
    assert _import_settings(DJANGO_DEBUG="True").returncode == 0


# ---------------------------------------------------------------- seed_demo
@pytest.mark.django_db
@override_settings(DEBUG=True)
def test_seed_demo_is_idempotent() -> None:
    call_command("seed_demo", stdout=io.StringIO())
    call_command("seed_demo", stdout=io.StringIO())
    assert set(Organization.objects.values_list("slug", flat=True)) == {"acme", "globex"}
    assert User.objects.count() == 5
    assert User.objects.get(email="root@platform.test").role == Role.SUPER_ADMIN
    assert User.objects.filter(organization__slug="acme", role=Role.ORG_ADMIN).count() == 1
    assert User.objects.get(email="bob@acme.test").check_password("Demo-Passw0rd!2026")


@pytest.mark.django_db
def test_seed_demo_refuses_production_without_force() -> None:
    with pytest.raises(CommandError, match="DEBUG=False"):
        call_command("seed_demo")
    call_command("seed_demo", "--force", stdout=io.StringIO())
    assert User.objects.count() == 5
