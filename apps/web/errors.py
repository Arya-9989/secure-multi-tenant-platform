"""Error responses: branded HTML pages for people, JSON for API clients.

Django's defaults are bare HTML everywhere, including under ``/api/``, where
clients expect DRF-style JSON. The pages need no inline code, so they render
correctly under the strict Content Security Policy; the CSRF failure page
replaces Django's, whose inline ``<style>`` the policy would block.
"""

from __future__ import annotations

import math
from typing import Any, NamedTuple

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.template import loader

from apps.common.context import get_request_context


class ErrorCopy(NamedTuple):
    title: str
    lead: str
    detail: str  # the JSON ``detail`` for API clients, worded like DRF's


ERRORS: dict[int, ErrorCopy] = {
    400: ErrorCopy(
        "That request didn’t make sense.",
        "The server couldn’t read it. Check the address and try again.",
        "Bad request.",
    ),
    403: ErrorCopy(
        "You can’t open this page.",
        "Your session may have expired, or the form was opened in another tab. "
        "Reload the page and try again.",
        "You do not have permission to perform this action.",
    ),
    404: ErrorCopy(
        "There’s nothing at this address.",
        "The page may have moved, or the link may be mistyped.",
        "Not found.",
    ),
    429: ErrorCopy(
        "Too many attempts.",
        "Sign-in is paused for this connection to protect the accounts on it.",
        "Request was throttled.",
    ),
    500: ErrorCopy(
        "Something went wrong on our side.",
        "The error has been logged. If it keeps happening, quote the request ID below.",
        "A server error occurred.",
    ),
}


def _wants_json(request: HttpRequest) -> bool:
    return request.path.startswith("/api/") and not request.path.startswith(
        ("/api/docs/", "/api/redoc/")
    )


def error_response(
    request: HttpRequest, status: int, *, retry_after: int | None = None
) -> HttpResponse:
    copy = ERRORS[status]
    response: HttpResponse
    if _wants_json(request):
        response = JsonResponse({"detail": copy.detail}, status=status)
    else:
        context: dict[str, Any] = {
            "status": status,
            "copy": copy,
            "retry_after": retry_after,
            "docs_enabled": settings.API_DOCS_ENABLED,
            "request_id": getattr(get_request_context(), "request_id", None),
        }
        # Rendered without a RequestContext: it must work even when context
        # processors (or the database behind them) are what failed.
        html = loader.get_template("web/error.html").render(context)
        response = HttpResponse(html, status=status)
    if retry_after is not None:
        response["Retry-After"] = str(retry_after)
    return response


def bad_request(request: HttpRequest, exception: Exception | None = None) -> HttpResponse:
    return error_response(request, 400)


def permission_denied(request: HttpRequest, exception: Exception | None = None) -> HttpResponse:
    return error_response(request, 403)


def page_not_found(request: HttpRequest, exception: Exception | None = None) -> HttpResponse:
    return error_response(request, 404)


def server_error(request: HttpRequest) -> HttpResponse:
    return error_response(request, 500)


def csrf_failure(request: HttpRequest, reason: str = "") -> HttpResponse:
    return error_response(request, 403)


def too_many_requests(request: HttpRequest, wait: float | None) -> HttpResponse:
    return error_response(request, 429, retry_after=math.ceil(wait) if wait else 60)
