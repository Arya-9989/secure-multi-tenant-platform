from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from rest_framework import serializers


class StrictFieldsMixin:
    """Reject unknown and read-only fields instead of silently ignoring them.

    DRF drops unexpected keys by default, which hides mass-assignment attempts
    (``{"role": "SUPER_ADMIN"}``, ``{"organization": ...}``) and client bugs.
    Failing loudly makes both visible and testable.
    """

    fields: Any

    def to_internal_value(self, data: Any) -> Any:
        if isinstance(data, Mapping):
            writable = {name for name, field in self.fields.items() if not field.read_only}
            unexpected = sorted(set(data) - writable)
            if unexpected:
                raise serializers.ValidationError(
                    {name: ["This field is not allowed."] for name in unexpected}
                )
        return super().to_internal_value(data)  # type: ignore[misc]


class StrictSerializer(StrictFieldsMixin, serializers.Serializer):  # type: ignore[type-arg]
    pass


class StrictModelSerializer(StrictFieldsMixin, serializers.ModelSerializer):  # type: ignore[type-arg]
    pass
