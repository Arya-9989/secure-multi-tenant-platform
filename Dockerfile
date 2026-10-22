# syntax=docker/dockerfile:1.7

ARG PYTHON_IMAGE=python:3.12-slim-trixie

# ------------------------------------------------------------------ builder
FROM ${PYTHON_IMAGE} AS builder

COPY --from=ghcr.io/astral-sh/uv:0.13.5 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /app

# Dependencies first, so source changes do not invalidate this layer.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project

COPY manage.py gunicorn.conf.py ./
COPY config ./config
COPY apps ./apps

# Collect static assets (admin, Swagger UI, Redoc) with throwaway build-time settings.
RUN DJANGO_SECRET_KEY=collectstatic-only-not-a-real-secret-0123456789 \
    /opt/venv/bin/python manage.py collectstatic --noinput --verbosity 0

# ------------------------------------------------------------------ runtime
FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="secure-multi-tenant-platform" \
      org.opencontainers.image.source="https://github.com/Arya-9989/secure-multi-tenant-platform" \
      org.opencontainers.image.licenses="MIT"

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=config.settings \
    PORT=8000

RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder --chown=app:app /app /app

USER app
EXPOSE 8000

# Liveness only (no dependencies). DJANGO_ALLOWED_HOSTS must include "localhost".
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import os, sys, urllib.request as u; r = u.Request(f\"http://127.0.0.1:{os.environ.get('PORT', '8000')}/health/live/\", headers={'Host': 'localhost'}); sys.exit(0 if u.urlopen(r, timeout=4).status == 200 else 1)"]

CMD ["gunicorn", "config.wsgi:application", "--config", "gunicorn.conf.py"]
