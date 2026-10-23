# ADR 0008: OpenTelemetry tracing, correlated with request IDs

- Status: accepted
- Date: 2026-10-23

## Context

Every request has an `X-Request-ID` that appears in the access log and in each audit event,
but there is no way to see where a slow request spent its time (the user lookup, the RLS
scope, a query, the cache, an IdP call), or to follow an invitation from the request that
created it into the worker that emailed it.

## Decision

- **OpenTelemetry SDK with the OTLP/HTTP exporter, switched on by configuration.** When
  `OTEL_EXPORTER_OTLP_ENDPOINT` (or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) is set,
  `apps.common.tracing.configure()` installs a tracer provider with a batch span processor
  and instruments psycopg, redis and urllib. When it is not set, nothing is installed: the
  API's default no-op tracer is used and the cost is a non-recording span object per
  request. `OTEL_TRACES_EXPORTER=console` prints spans instead, and the standard
  `OTEL_TRACES_SAMPLER` / `OTEL_TRACES_SAMPLER_ARG` variables choose the sampler (parent-based,
  always-on by default). It is configured in `wsgi.py` (in each gunicorn worker, after the
  fork, so the exporter's thread is not shared across processes) and in `manage.py` for
  commands such as the task worker.
- **Our own server-span middleware instead of the Django instrumentation.** The stock
  instrumentation records the full URL with its query string, the client address and the
  user agent. A query string here can hold an email (`?email=`, `?search=`), so the platform
  writes the server span itself and chooses every attribute: the method, the **route
  template** (`api/v1/users/<pk>/`, never the concrete path with IDs), the status code,
  `request.id` (the same value as `X-Request-ID`, so logs, audit events and traces join),
  and `tenant.id`, the organization UUID of the authenticated caller, set when
  authentication binds the database scope. Incoming `traceparent` headers are honoured, so
  a gateway's trace continues here.
- **No PII.** No email, name, IP address, user agent, token or query string is ever put on
  a span. Database spans carry the SQL text with its placeholders (psycopg's instrumentation
  records statements, not parameters) and redis spans the command name only. A test sends
  requests full of personal data and checks no span attribute contains it.
- **Across the task queue.** `enqueue()` stores the current trace context on the task row;
  the worker starts each task's span as a child of it, with `task.name`, `task.attempt` and
  `tenant.id`. One trace runs from `POST /invitations/` to the SMTP call.
- **Logs.** JSON log lines carry `trace_id` and `span_id` when a span is recording.
- **Locally**, Jaeger (`docker compose --profile tracing`) receives OTLP on port 4318 and
  shows the traces.

## Consequences

- Tracing is opt-in per deployment, costs nothing when off, and cannot leak personal data
  through attributes the platform does not control.
- Dropping the Django instrumentation means its `http.*` semantic-convention attributes
  beyond the ones chosen here are absent; the route template and status are what dashboards
  need.
- A span processor exports from a background thread; `configure()` registers a shutdown
  hook so pending spans are flushed when a worker exits.
