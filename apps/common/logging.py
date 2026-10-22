"""Structured (JSON) logging with the request ID attached to every record."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from apps.common.context import get_request_context

_RESERVED_ATTRS = frozenset(
    vars(logging.LogRecord("", logging.INFO, "", 0, "", (), None)).keys()
    | {"message", "asctime", "request_id"}
)


class RequestContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        context = get_request_context()
        record.request_id = context.request_id if context else "-"
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line; ``extra=`` fields become top-level keys."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED_ATTRS and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)
