"""Per-request context (request ID, client IP, user agent).

Stored in a ``ContextVar`` so it is available to logging and the audit log
without threading the request object through every service function. It is
bound and reset by :class:`apps.common.middleware.RequestContextMiddleware`.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RequestContext:
    request_id: str
    ip_address: str | None
    user_agent: str


_current: ContextVar[RequestContext | None] = ContextVar("request_context", default=None)


def get_request_context() -> RequestContext | None:
    return _current.get()


def bind_request_context(context: RequestContext) -> Token[RequestContext | None]:
    return _current.set(context)


def reset_request_context(token: Token[RequestContext | None]) -> None:
    _current.reset(token)
