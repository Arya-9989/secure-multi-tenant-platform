"""The last step of every sign-in: password, second factor or SSO (ADRs 0002-0004)."""

from __future__ import annotations

from typing import Any

from django.contrib.auth.models import update_last_login
from rest_framework.request import Request
from rest_framework.response import Response

from apps.accounts import login_throttle, sessions
from apps.accounts.models import User
from apps.auditlogs.models import AuditAction
from apps.auditlogs.services import record


def complete(
    request: Request,
    user: User,
    *,
    decision: login_throttle.Decision | None = None,
    metadata: dict[str, Any] | None = None,
) -> Response:
    """Start the session, audit it, trust the device, clear the throttle bucket."""
    if decision is not None:
        login_throttle.succeeded(decision)
    refresh = sessions.start(user)
    update_last_login(type(user), user)
    record(
        AuditAction.LOGIN_SUCCEEDED,
        actor=user,
        organization=user.organization,
        metadata=metadata or {},
    )
    response = Response({"access": str(refresh.access_token), "refresh": str(refresh)})
    login_throttle.set_device_cookie(response, request, user.email)
    return response
