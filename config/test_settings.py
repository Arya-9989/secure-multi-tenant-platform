"""Settings used by the test suite and type checker.

Imports the real settings so tests exercise production configuration, with
only the minimum overridden for speed and determinism.
"""

import os

os.environ.setdefault("DJANGO_SECRET_KEY", "test-only-secret-key-not-used-anywhere-else-0123456789")
os.environ.setdefault("DJANGO_ALLOWED_HOSTS", "testserver,localhost")
os.environ.setdefault("DJANGO_SECURE_SSL_REDIRECT", "False")
os.environ.setdefault("LOG_LEVEL", "WARNING")
# The suite connects as the owner to build the test database, then works as the
# runtime role (tests/conftest.py), so the connection check is done by tests.
os.environ.setdefault("DATABASE_REQUIRE_RLS", "False")

from config.settings import *  # noqa: F403

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}
