"""OpenAPI integration: describe our JWT authentication class to drf-spectacular."""

from __future__ import annotations

from typing import Any

from drf_spectacular.contrib.rest_framework_simplejwt import SimpleJWTScheme


class TenantJWTScheme(SimpleJWTScheme):
    target_class = "apps.accounts.authentication.TenantJWTAuthentication"
    name = "jwtAuth"

    def get_security_definition(self, auto_schema: Any) -> dict[str, Any]:
        definition: dict[str, Any] = super().get_security_definition(auto_schema)
        definition["description"] = (
            "Paste the `access` token from `POST /api/v1/auth/login/`. Access tokens live "
            "5 minutes; rotate with `POST /api/v1/auth/refresh/`."
        )
        return definition
