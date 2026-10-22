"""OpenAPI generation: document the error responses every endpoint can return."""

from __future__ import annotations

from typing import Any

from drf_spectacular.openapi import AutoSchema as SpectacularAutoSchema
from drf_spectacular.utils import OpenApiResponse
from rest_framework import serializers


class ErrorSerializer(serializers.Serializer[Any]):
    detail = serializers.CharField()


# {"<field>": ["message", ...], ...}
VALIDATION_ERRORS = {
    "type": "object",
    "additionalProperties": {"type": "array", "items": {"type": "string"}},
    "example": {"role": ['"SUPER_ADMIN" is not a valid choice.']},
}


_ERRORS = {
    "400": OpenApiResponse(
        VALIDATION_ERRORS,
        description="Validation failed. Unknown or read-only fields are rejected too.",
    ),
    "401": OpenApiResponse(ErrorSerializer, description="Missing, expired or revoked token."),
    "403": OpenApiResponse(ErrorSerializer, description="Your role may not perform this action."),
    "404": OpenApiResponse(
        ErrorSerializer,
        description="Not found - or owned by another organization (deliberately identical).",
    ),
}


class AutoSchema(SpectacularAutoSchema):
    def _get_response_bodies(self, direction: Any = "response") -> Any:
        responses = super()._get_response_bodies(direction)
        if direction != "response":
            return responses
        codes: list[str] = []
        if self.method in {"POST", "PUT", "PATCH"} and self.get_request_serializer():
            codes.append("400")
        if any(self.get_auth()):  # empty for public endpoints
            codes += ["401", "403"]
            if "{" in self.path:
                codes.append("404")
        for code in codes:
            if code not in responses:
                responses[code] = self._get_response_for_code(_ERRORS[code], code)
        return responses
