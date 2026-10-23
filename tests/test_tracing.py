"""OpenTelemetry tracing (ADR 0008): spans named by route, request IDs and tenants on
them, traces that continue across services and into the task worker, and no
personal data anywhere."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from django.db import connections
from django.urls import reverse
from opentelemetry import trace
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode
from rest_framework.test import APIClient

from apps.common import tracing
from apps.common.logging import JsonFormatter, RequestContextFilter
from apps.tasks import worker
from tests.conftest import PASSWORD, POSTGRES, ClientFactory, World

pytestmark = pytest.mark.django_db

ROOT = Path(__file__).resolve().parent.parent
EXPORTER = InMemorySpanExporter()


@pytest.fixture(scope="module", autouse=True)
def _tracing_on() -> None:
    """The SDK can be installed once per process; the spans go to memory here."""
    tracing.configure(span_processor=SimpleSpanProcessor(EXPORTER))
    for connection in connections.all():
        connection.close()  # psycopg is instrumented from the next connection on


@pytest.fixture
def spans() -> Iterator[InMemorySpanExporter]:
    EXPORTER.clear()
    yield EXPORTER
    EXPORTER.clear()


def server_spans(exporter: InMemorySpanExporter) -> list[ReadableSpan]:
    return [s for s in exporter.get_finished_spans() if s.kind == SpanKind.SERVER]


# ---------------------------------------------------------------- the server span
def test_requests_are_spans_named_by_route_with_request_and_tenant_ids(
    world: World, client_for: ClientFactory, spans: InMemorySpanExporter
) -> None:
    response = client_for(world.admin_a).get(
        reverse("user-detail", args=[world.member_a.pk]), HTTP_X_REQUEST_ID="trace-me-0001"
    )
    assert response.status_code == 200
    (span,) = server_spans(spans)
    assert span.name == "GET api/v1/users/<pk>/"
    attributes = dict(span.attributes or {})
    assert attributes["http.route"] == "api/v1/users/<pk>/"
    assert attributes["request.id"] == "trace-me-0001" == response["X-Request-ID"]
    assert attributes["tenant.id"] == str(world.org_a.pk)
    assert attributes["http.response.status_code"] == 200
    assert str(world.member_a.pk) not in span.name, "the template, not the concrete path"


def test_super_admin_requests_carry_no_tenant(
    world: World, client_for: ClientFactory, spans: InMemorySpanExporter
) -> None:
    client_for(world.super_admin).get(reverse("organization-list"))
    (span,) = server_spans(spans)
    assert "tenant.id" not in (span.attributes or {})


def test_an_incoming_trace_is_continued(world: World, spans: InMemorySpanExporter) -> None:
    trace_id, parent_id = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
    APIClient().get("/health/live/", HTTP_TRACEPARENT=f"00-{trace_id}-{parent_id}-01")
    (span,) = server_spans(spans)
    assert format(span.context.trace_id, "032x") == trace_id
    assert span.parent is not None
    assert format(span.parent.span_id, "016x") == parent_id


def test_server_errors_mark_the_span(
    world: World, spans: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("kaboom")

    monkeypatch.setattr("apps.common.views.readiness_checks", boom)
    client = APIClient()
    client.raise_request_exception = False
    assert client.get("/health/ready/").status_code == 500
    (span,) = server_spans(spans)
    assert span.status.status_code == StatusCode.ERROR


def test_unknown_routes_are_not_named_after_their_path(spans: InMemorySpanExporter) -> None:
    APIClient().get("/api/v1/no/such/alice@acme.test/")
    (span,) = server_spans(spans)
    assert span.name == "GET"


@pytest.mark.skipif(not POSTGRES, reason="psycopg instrumentation (PostgreSQL)")
def test_queries_are_child_spans_without_their_parameters(
    world: World, spans: InMemorySpanExporter
) -> None:
    APIClient().post(reverse("auth-login"), {"email": "member@a.test", "password": PASSWORD})
    (server,) = server_spans(spans)
    queries = [s for s in spans.get_finished_spans() if s.kind == SpanKind.CLIENT]
    assert queries, "database calls are traced"
    assert all(q.context.trace_id == server.context.trace_id for q in queries)
    statements = " ".join(str((q.attributes or {}).get("db.statement", "")) for q in queries)
    assert "set_config('app.tenant_id'" in statements, "the RLS scope is visible in traces"
    assert "member@a.test" not in statements


# ---------------------------------------------------------------- no personal data
def test_no_span_carries_personal_data(
    world: World, client_for: ClientFactory, spans: InMemorySpanExporter
) -> None:
    secrets_and_pii = [
        "member@a.test",
        "carol@a.test",
        "alice",
        PASSWORD,
        "203.0.113.77",  # the client's address (the database's own address is not PII)
        "pii-test-agent/1.0",
        "Bob Builder",
    ]
    client = APIClient(HTTP_USER_AGENT="pii-test-agent/1.0", REMOTE_ADDR="203.0.113.77")
    tokens = client.post(
        reverse("auth-login"), {"email": "member@a.test", "password": PASSWORD}
    ).json()
    secrets_and_pii += [tokens["access"], tokens["refresh"]]
    admin = client_for(world.admin_a)
    admin.post(reverse("invitation-list"), {"email": "carol@a.test", "role": "MEMBER"})
    admin.get(reverse("user-list"), {"search": "alice", "email": "carol@a.test"})
    member = APIClient(HTTP_USER_AGENT="pii-test-agent/1.0", REMOTE_ADDR="203.0.113.77")
    member.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
    member.patch(reverse("auth-me"), {"full_name": "Bob Builder"})
    worker.drain()

    recorded = spans.get_finished_spans()
    assert len(recorded) >= 5
    for span in recorded:
        values = [span.name, *(str(v) for v in (span.attributes or {}).values())]
        for event in span.events:
            values += [str(v) for v in (event.attributes or {}).values()]
        for value in values:
            for secret in secrets_and_pii:
                assert secret not in value, f"{secret!r} in span {span.name!r}: {value!r}"


# ---------------------------------------------------------------- across the task queue
def test_the_worker_continues_the_trace_of_the_request_that_queued_the_task(
    world: World, client_for: ClientFactory, spans: InMemorySpanExporter
) -> None:
    client_for(world.admin_a).post(
        reverse("invitation-list"), {"email": "carol@a.test", "role": "MEMBER"}
    )
    (request_span,) = server_spans(spans)
    worker.drain()
    (task_span,) = [s for s in spans.get_finished_spans() if s.name.startswith("task ")]
    assert task_span.name == "task send_invitation_email"
    assert task_span.context.trace_id == request_span.context.trace_id
    attributes = dict(task_span.attributes or {})
    assert attributes["task.name"] == "apps.accounts.tasks.send_invitation_email"
    assert attributes["task.attempt"] == 1
    assert attributes["tenant.id"] == str(world.org_a.pk)


def test_a_failing_task_records_its_error(spans: InMemorySpanExporter) -> None:
    from tests import task_fixtures  # noqa: PLC0415

    task_fixtures.always_fails.enqueue()
    worker.run_once()
    (span,) = [s for s in spans.get_finished_spans() if s.name.startswith("task ")]
    assert span.status.status_code == StatusCode.ERROR
    assert span.events[0].name == "exception"


# ---------------------------------------------------------------- logs and helpers
def test_log_lines_carry_the_trace_and_span_ids(spans: InMemorySpanExporter) -> None:
    record = logging.LogRecord("apps.test", logging.INFO, __file__, 1, "inside", (), None)
    with tracing.tracer().start_as_current_span("unit") as span:
        RequestContextFilter().filter(record)
        payload = json.loads(JsonFormatter().format(record))
    assert payload["trace_id"] == format(span.get_span_context().trace_id, "032x")
    assert payload["span_id"] == format(span.get_span_context().span_id, "016x")
    outside = json.loads(JsonFormatter().format(record))
    assert "trace_id" not in outside


def test_helpers_are_harmless_without_a_span() -> None:
    assert tracing.current_traceparent() == ""
    assert tracing.trace_ids() == {}
    tracing.set_tenant("00000000-0000-0000-0000-000000000000")  # no current span: no-op
    assert tracing.configure() is True, "configuring twice is a no-op"
    assert isinstance(trace.get_current_span(), trace.NonRecordingSpan)


def _probe(**env: str) -> str:
    clean = {k: v for k, v in os.environ.items() if not k.startswith("OTEL_")}
    code = (
        "import django, os;"
        "os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.test_settings');"
        "django.setup(); from apps.common import tracing; from opentelemetry import trace;"
        "print(tracing.configure(), type(trace.get_tracer_provider()).__name__)"
    )
    result = subprocess.run(  # noqa: S603 - our own interpreter
        [sys.executable, "-c", code],
        cwd=ROOT,
        env={**clean, **env},
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip().splitlines()[-1]


def test_tracing_is_a_no_op_until_an_exporter_is_configured() -> None:
    assert _probe() == "False ProxyTracerProvider"
    assert _probe(OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:9") == "True TracerProvider"
    assert _probe(OTEL_TRACES_EXPORTER="console") == "True TracerProvider"
