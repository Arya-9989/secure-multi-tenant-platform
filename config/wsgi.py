"""WSGI entrypoint (used by gunicorn)."""

import os

from django.core.wsgi import get_wsgi_application

from apps.common import tracing

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

# Gunicorn imports this in each worker after forking, so the span exporter's
# thread belongs to that worker. A no-op unless an exporter is configured.
tracing.configure()

application = get_wsgi_application()
