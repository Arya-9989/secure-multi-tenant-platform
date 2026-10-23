"""OpenAPI: describe API-key authentication to drf-spectacular."""

from __future__ import annotations

from typing import Any

from drf_spectacular.extensions import OpenApiAuthenticationExtension


class ApiKeyScheme(OpenApiAuthenticationExtension):
    target_class = "apps.apikeys.authentication.ApiKeyAuthentication"
    name = "apiKeyAuth"

    def get_security_definition(self, auto_schema: Any) -> dict[str, Any]:
        return {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": (
                "For services: `ApiKey mtk_<prefix>_<secret>`. Read-only, tenant-bound, "
                "scoped per endpoint; issue one at `POST /api/v1/api-keys/`."
            ),
        }
