from __future__ import annotations

import logging
import re
import time
import uuid
from collections.abc import Callable

from django.http import HttpRequest, HttpResponse

from apps.common import rls
from apps.common.context import RequestContext, bind_request_context, reset_request_context
from apps.common.net import get_client_ip

logger = logging.getLogger("apps.access")

REQUEST_ID_HEADER = "X-Request-ID"
# A caller-supplied request ID (e.g. from a load balancer) is only accepted if it
# is short and boring; anything else is replaced, which prevents log injection.
_VALID_REQUEST_ID = re.compile(r"[A-Za-z0-9._-]{8,64}")


class RequestContextMiddleware:
    """Assigns a request ID, binds request context and emits one access-log line."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        incoming = request.headers.get(REQUEST_ID_HEADER, "")
        request_id = incoming if _VALID_REQUEST_ID.fullmatch(incoming) else uuid.uuid4().hex
        context = RequestContext(
            request_id=request_id,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent", "")[:512],
        )
        token = bind_request_context(context)
        started = time.perf_counter()
        try:
            # Every request starts with no database scope and authentication binds
            # the caller's (row-level security, ADR 0001); the block undoes it.
            with rls.scope(rls.NO_SCOPE):
                response = self.get_response(request)
            response[REQUEST_ID_HEADER] = request_id
            _log_access(request, response, started)
            return response
        finally:
            reset_request_context(token)


def _log_access(request: HttpRequest, response: HttpResponse, started: float) -> None:
    # DRF writes the JWT-authenticated user back onto the Django request, so by
    # the time the response is returned this reflects the API caller.
    user = getattr(request, "user", None)
    user_id = organization_id = None
    if user is not None and user.is_authenticated:
        user_id = str(user.pk)
        org_id = getattr(user, "organization_id", None)
        organization_id = str(org_id) if org_id else None
    level = logging.DEBUG if request.path.startswith("/health/") else logging.INFO
    logger.log(
        level,
        "%s %s %s",
        request.method,
        request.path,
        response.status_code,
        extra={
            "http_method": request.method,
            "path": request.path,
            "status_code": response.status_code,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "user_id": user_id,
            "organization_id": organization_id,
        },
    )
