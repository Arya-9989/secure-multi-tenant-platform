"""Django settings, configured entirely from environment variables.

Defaults are secure (``DEBUG`` off, HTTPS enforced, secret required). Local
development opts *out* of those via ``.env`` - see ``.env.example``.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import django_stubs_ext
import environ
from django.core.exceptions import ImproperlyConfigured
from django.utils.csp import CSP

# Lets Django's classes be subscripted at runtime (e.g. ``ModelAdmin[User]``).
django_stubs_ext.monkeypatch()

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env()
environ.Env.read_env(BASE_DIR / ".env", overwrite=False)

# ---------------------------------------------------------------- core
DEBUG: bool = env.bool("DJANGO_DEBUG", default=False)
SECRET_KEY: str = env.str("DJANGO_SECRET_KEY", default="")
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set when DJANGO_DEBUG is false.")
    SECRET_KEY = "insecure-development-only-key-do-not-use-in-production"  # noqa: S105

ALLOWED_HOSTS: list[str] = env.list(
    "DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"] if DEBUG else []
)
CSRF_TRUSTED_ORIGINS: list[str] = env.list("DJANGO_CSRF_TRUSTED_ORIGINS", default=[])

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # third party
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "django_filters",
    "drf_spectacular",
    "drf_spectacular_sidecar",
    # local
    "apps.common",
    "apps.organizations",
    "apps.accounts",
    "apps.auditlogs",
    "apps.web",
    # django.contrib.admin, hardened (apps.common.admin_site). Listed after
    # apps.web so that app's admin/base_site.html (theme, icon) takes precedence.
    "apps.common.apps.PlatformAdminConfig",
]

MIDDLEWARE = [
    "apps.common.middleware.RequestContextMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.csp.ContentSecurityPolicyMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.csp",
            ],
        },
    },
]

# ---------------------------------------------------------------- data
DATABASES = {
    "default": env.db_url("DATABASE_URL", default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}"),
}
DATABASES["default"]["CONN_MAX_AGE"] = env.int("DATABASE_CONN_MAX_AGE", default=60)
DATABASES["default"]["CONN_HEALTH_CHECKS"] = True
# PostgreSQL row-level security (ADR 0001): this backend applies the current
# tenant scope to every statement, and the policies fail closed without one.
if DATABASES["default"]["ENGINE"] == "django.db.backends.postgresql":
    DATABASES["default"]["ENGINE"] = "apps.common.pgbackend"
# The role the API connects as. Migrations grant it data privileges; it must not
# own the schema, be a superuser or have BYPASSRLS.
DATABASE_RUNTIME_ROLE: str = env.str("DATABASE_RUNTIME_ROLE", default="app_runtime")
# Refuse database connections whose role would ignore row-level security. Off
# for migrations and operator commands, which connect as the owner.
DATABASE_REQUIRE_RLS: bool = env.bool("DATABASE_REQUIRE_RLS", default=not DEBUG)
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REDIS_URL: str = env.str("REDIS_URL", default="")
CACHES = {
    "default": (
        {"BACKEND": "django.core.cache.backends.redis.RedisCache", "LOCATION": REDIS_URL}
        if REDIS_URL
        else {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    )
}

# ---------------------------------------------------------------- auth
AUTH_USER_MODEL = "accounts.User"
# Resolves the account's tenant before loading it, so sign-in and session lookups
# work under row-level security (apps.accounts.backends).
AUTHENTICATION_BACKENDS = ["apps.accounts.backends.TenantModelBackend"]
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": env.int("PASSWORD_MIN_LENGTH", default=12)},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

INVITATION_TTL = timedelta(hours=env.int("INVITATION_TTL_HOURS", default=72))
FRONTEND_INVITE_URL: str = env.str(
    "FRONTEND_INVITE_URL", default="http://localhost:3000/accept-invite?token={token}"
)
DEFAULT_FROM_EMAIL: str = env.str("DEFAULT_FROM_EMAIL", default="no-reply@localhost")
EMAIL_BACKEND: str = env.str(
    "EMAIL_BACKEND", default="django.core.mail.backends.console.EmailBackend"
)

# ---------------------------------------------------------------- DRF / JWT
# Number of trusted reverse proxies in front of the app. Used both for DRF
# throttling and for the client IP recorded in the audit log. 0 = ignore
# X-Forwarded-For entirely (safe default: the header is attacker-controlled).
NUM_PROXIES: int = env.int("NUM_PROXIES", default=0)

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ("apps.accounts.authentication.TenantJWTAuthentication",),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_FILTER_BACKENDS": (
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ),
    "DEFAULT_PAGINATION_CLASS": "apps.common.pagination.DefaultPagination",
    "DEFAULT_RENDERER_CLASSES": ("rest_framework.renderers.JSONRenderer",),
    "DEFAULT_PARSER_CLASSES": ("rest_framework.parsers.JSONParser",),
    "DEFAULT_SCHEMA_CLASS": "apps.common.schema.AutoSchema",
    # Keyed on the same client IP as the audit log (see apps.common.throttling).
    "DEFAULT_THROTTLE_CLASSES": (
        "apps.common.throttling.ClientAnonRateThrottle",
        "apps.common.throttling.ClientUserRateThrottle",
    ),
    "DEFAULT_THROTTLE_RATES": {
        "anon": env.str("THROTTLE_ANON", default="60/min"),
        "user": env.str("THROTTLE_USER", default="600/min"),
        "auth": env.str("THROTTLE_AUTH", default="10/min"),
    },
    # 0, not None: DRF treats None as "trust X-Forwarded-For as sent".
    "NUM_PROXIES": NUM_PROXIES,
    "TEST_REQUEST_DEFAULT_FORMAT": "json",
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=env.int("JWT_ACCESS_TTL_MINUTES", default=5)),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=env.int("JWT_REFRESH_TTL_DAYS", default=1)),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": env.str("JWT_SIGNING_KEY", default=SECRET_KEY),
    "AUDIENCE": env.str("JWT_AUDIENCE", default="secure-multi-tenant-platform"),
    "ISSUER": env.str("JWT_ISSUER", default="secure-multi-tenant-platform"),
    "LEEWAY": 5,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "USER_AUTHENTICATION_RULE": "apps.accounts.authentication.user_can_authenticate",
}
if not DEBUG and len(SIMPLE_JWT["SIGNING_KEY"]) < 32:
    raise ImproperlyConfigured("The JWT signing key must be at least 32 characters (RFC 7518).")

API_DOCS_ENABLED: bool = env.bool("API_DOCS_ENABLED", default=True)
SPECTACULAR_SETTINGS = {
    "TITLE": "Secure Multi-Tenant Platform API",
    "DESCRIPTION": (
        "Multi-tenant SaaS backend with organization-level isolation, role-based access "
        "control, token-based invitations and an append-only audit log.\n\n"
        "**Try it:** run `python manage.py seed_demo`, call `POST /api/v1/auth/login/` with "
        "one of the printed accounts, click **Authorize** and paste the `access` token. "
        "Then try to read another organization's data - you will get `404`."
    ),
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "SCHEMA_PATH_PREFIX": r"/api/v1",
    "COMPONENT_SPLIT_REQUEST": True,
    "ENUM_NAME_OVERRIDES": {
        "RoleEnum": "apps.accounts.roles.Role",
        "AssignableRoleEnum": "apps.accounts.roles.ASSIGNABLE_ROLE_CHOICES",
    },
    "SWAGGER_UI_DIST": "SIDECAR",
    "SWAGGER_UI_FAVICON_HREF": "SIDECAR",
    "REDOC_DIST": "SIDECAR",
    "SWAGGER_UI_SETTINGS": {
        # The open operation is mirrored in the URL. apps/web/static/web/js/
        # swagger-plugins.js keeps that accessible (no link nested in a button).
        "deepLinking": True,
        "persistAuthorization": True,
        "displayRequestDuration": True,
        "filter": True,
        "docExpansion": "list",
        "defaultModelsExpandDepth": 0,
        "tryItOutEnabled": True,
    },
    "TAGS": [
        {"name": "auth", "description": "Login, token rotation, logout and own profile."},
        {"name": "organizations", "description": "Tenants. Created and managed by super admins."},
        {"name": "users", "description": "Tenant-scoped user directory and administration."},
        {"name": "invitations", "description": "Expiring, single-use, token-based onboarding."},
        {"name": "audit-logs", "description": "Append-only, tenant-scoped security audit trail."},
        {"name": "health", "description": "Liveness and readiness probes."},
    ],
}

# ---------------------------------------------------------------- security
if env.bool("DJANGO_BEHIND_TLS_PROXY", default=False):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT: bool = env.bool("DJANGO_SECURE_SSL_REDIRECT", default=not DEBUG)
SECURE_REDIRECT_EXEMPT = [r"^health/"]
SECURE_HSTS_SECONDS: int = env.int("DJANGO_SECURE_HSTS_SECONDS", default=0 if DEBUG else 31536000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
# Preload-list submission is a hard-to-reverse commitment for the whole domain,
# so it is opt-in; its deploy-check warning is silenced deliberately.
SECURE_HSTS_PRELOAD: bool = env.bool("DJANGO_SECURE_HSTS_PRELOAD", default=False)
SILENCED_SYSTEM_CHECKS = ["security.W021"]
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SESSION_COOKIE_SECURE: bool = env.bool("DJANGO_SECURE_COOKIES", default=not DEBUG)
CSRF_COOKIE_SECURE: bool = SESSION_COOKIE_SECURE
SESSION_COOKIE_HTTPONLY = True
X_FRAME_OPTIONS = "DENY"
# One strict policy for every response: the landing page, Swagger UI, Redoc
# and the admin load only same-origin scripts, styles and fonts, with no
# inline code. Redoc injects its styles at runtime and indexes search in a
# blob: worker, so its view adds a per-response style nonce and worker-src
# (see apps.web.views.ThemedRedocView).
SECURE_CSP = {
    "default-src": [CSP.SELF],
    "script-src": [CSP.SELF],
    "style-src": [CSP.SELF],
    "img-src": [CSP.SELF, "data:"],
    "font-src": [CSP.SELF],
    "connect-src": [CSP.SELF],
    "object-src": [CSP.NONE],
    "base-uri": [CSP.NONE],
    "form-action": [CSP.SELF],
    "frame-ancestors": [CSP.NONE],
}
# Django's own CSRF failure page uses an inline <style>, which the CSP blocks.
CSRF_FAILURE_VIEW = "apps.web.errors.csrf_failure"
DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024
ADMIN_URL: str = env.str("DJANGO_ADMIN_URL", default="admin/")

# ---------------------------------------------------------------- i18n / static
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": (
            "django.contrib.staticfiles.storage.StaticFilesStorage"
            if DEBUG
            else "whitenoise.storage.CompressedManifestStaticFilesStorage"
        )
    },
}

# ---------------------------------------------------------------- logging
LOG_LEVEL: str = env.str("LOG_LEVEL", default="INFO")
LOG_FORMAT: str = env.str("LOG_FORMAT", default="json")
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {"request_context": {"()": "apps.common.logging.RequestContextFilter"}},
    "formatters": {
        "json": {"()": "apps.common.logging.JsonFormatter"},
        "console": {
            "format": "%(asctime)s %(levelname)-8s [%(request_id)s] %(name)s: %(message)s",
        },
    },
    "handlers": {
        "stdout": {
            "class": "logging.StreamHandler",
            "formatter": LOG_FORMAT,
            "filters": ["request_context"],
        },
    },
    "root": {"handlers": ["stdout"], "level": LOG_LEVEL},
    "loggers": {
        # The access log is emitted by RequestContextMiddleware; avoid duplicates.
        "django.request": {"level": "ERROR"},
        "django.server": {"level": "WARNING"},
    },
}
