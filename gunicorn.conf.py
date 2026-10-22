"""Gunicorn configuration (12-factor: everything overridable via environment)."""

import multiprocessing
import os

bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"
workers = int(os.environ.get("GUNICORN_WORKERS", min(multiprocessing.cpu_count() * 2 + 1, 8)))
threads = int(os.environ.get("GUNICORN_THREADS", "2"))
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "30"))
graceful_timeout = 30
keepalive = 5

# Recycle workers periodically to contain slow memory growth.
max_requests = 1000
max_requests_jitter = 100

# Heartbeat files on tmpfs avoid stalls on slow container filesystems.
worker_tmp_dir = "/dev/shm"  # noqa: S108

# The application emits one structured access-log line per request itself.
accesslog = None
errorlog = "-"
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "info")

# Only trust X-Forwarded-* from these addresses (your load balancer).
forwarded_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1")
