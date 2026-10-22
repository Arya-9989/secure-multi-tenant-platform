"""OpenTelemetry tracing, off unless an exporter is configured (ADR 0008).

``configure()`` installs the SDK only when ``OTEL_EXPORTER_OTLP_ENDPOINT`` (or the
traces-specific variable) is set, or ``OTEL_TRACES_EXPORTER=console``. Otherwise
the OpenTelemetry API's no-op tracer stays in place.

Spans never carry personal data: the server span (``TracingMiddleware``) records
the route *template*, the status, ``request.id`` and ``tenant.id`` (an
organization UUID); database spans carry SQL with placeholders; redis spans the
command name only.
"""

from __future__ import annotations

import atexit
import logging
import os
from collections.abc import Callable
from typing import Any

from opentelemetry import context as otel_context
from opentelemetry import propagate, trace
from opentelemetry.trace import Span, SpanKind, Status, StatusCode

logger = logging.getLogger(__name__)

TRACER_NAME = "secure-multi-tenant-platform"
_configured = False


def exporter_configured() -> bool:
    return bool(
        os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        or os.environ.get("OTEL_TRACES_EXPORTER") == "console"
    )


def configure(service_name: str = TRACER_NAME, *, span_processor: Any = None) -> bool:
    """Install the SDK and instrumentations once. ``False`` (no-op) when not configured.

    ``span_processor`` replaces the exporter (tests pass an in-memory one).
    """
    global _configured  # noqa: PLW0603 - process-wide, once
    if _configured:
        return True
    if span_processor is None and not exporter_configured():
        return False

    from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor  # noqa: PLC0415
    from opentelemetry.instrumentation.redis import RedisInstrumentor  # noqa: PLC0415
    from opentelemetry.instrumentation.urllib import URLLibInstrumentor  # noqa: PLC0415
    from opentelemetry.sdk.resources import Resource  # noqa: PLC0415
    from opentelemetry.sdk.trace import TracerProvider  # noqa: PLC0415
    from opentelemetry.sdk.trace.export import (  # noqa: PLC0415
        BatchSpanProcessor,
        ConsoleSpanExporter,
    )

    resource = Resource.create(
        {
            "service.name": os.environ.get("OTEL_SERVICE_NAME", service_name),
            "deployment.environment": os.environ.get("DEPLOYMENT_ENVIRONMENT", "local"),
        }
    )
    provider = TracerProvider(resource=resource)  # sampler from OTEL_TRACES_SAMPLER
    if span_processor is None:
        if os.environ.get("OTEL_TRACES_EXPORTER") == "console":
            span_processor = BatchSpanProcessor(ConsoleSpanExporter())
        else:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # noqa: PLC0415
                OTLPSpanExporter,
            )

            span_processor = BatchSpanProcessor(OTLPSpanExporter())
    provider.add_span_processor(span_processor)
    trace.set_tracer_provider(provider)
    atexit.register(provider.shutdown)

    # Statements with placeholders, never their parameters; no SQL comments added.
    PsycopgInstrumentor().instrument(enable_commenter=False, capture_parameters=False)
    RedisInstrumentor().instrument()  # sanitised: "INCR ?" rather than the key
    URLLibInstrumentor().instrument()  # IdP and SIEM calls
    _configured = True
    logger.info("OpenTelemetry tracing enabled for %s", service_name)
    return True


def tracer() -> trace.Tracer:
    return trace.get_tracer(TRACER_NAME)


def set_tenant(tenant_id: Any) -> None:
    """Tag the current span with the caller's organization (an ID, never a name)."""
    span = trace.get_current_span()
    if span.is_recording() and tenant_id:
        span.set_attribute("tenant.id", str(tenant_id))


def current_traceparent() -> str:
    """The W3C ``traceparent`` of the current span ("" when not tracing)."""
    carrier: dict[str, str] = {}
    propagate.inject(carrier)
    return carrier.get("traceparent", "")


def run_in_trace(
    name: str, traceparent: str, attributes: dict[str, Any], body: Callable[[], Any]
) -> Any:
    """Run ``body`` in a span that continues the trace ``traceparent`` belongs to."""
    parent = propagate.extract({"traceparent": traceparent}) if traceparent else None
    token = otel_context.attach(parent) if parent is not None else None
    try:
        with tracer().start_as_current_span(
            name, kind=SpanKind.CONSUMER, attributes=attributes
        ) as span:
            return _record_errors(span, body)
    finally:
        if token is not None:
            otel_context.detach(token)


def _record_errors(span: Span, body: Callable[[], Any]) -> Any:
    try:
        return body()
    except Exception as exc:
        span.record_exception(exc)
        span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
        raise


def trace_ids() -> dict[str, str]:
    """``trace_id`` and ``span_id`` of the current recording span, for log lines."""
    span_context = trace.get_current_span().get_span_context()
    if not span_context.is_valid:
        return {}
    return {
        "trace_id": format(span_context.trace_id, "032x"),
        "span_id": format(span_context.span_id, "016x"),
    }
