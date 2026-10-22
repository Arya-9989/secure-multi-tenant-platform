"""The Django admin site, held to the same standards as the API.

The admin is a second way in for super admins, so its sign-in is throttled with
the API's credential rate and audited like an API login, and a password changed
here revokes every API session exactly as ``POST /auth/password/change/`` does.
"""

from __future__ import annotations

from typing import Any

from django.contrib import admin
from django.contrib.auth import update_session_auth_hash
from django.db import transaction
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.template.response import TemplateResponse

from apps.accounts import services
from apps.accounts.models import SessionEndReason
from apps.auditlogs.models import AuditAction
from apps.auditlogs.services import record
from apps.common.tenancy import resolve_user
from apps.common.throttling import AdminLoginThrottle
from apps.web.errors import too_many_requests

ADMIN_CHANNEL = "admin"


class PlatformAdminSite(admin.AdminSite):
    site_header = "Secure Multi-Tenant Platform"
    site_title = "Platform admin"
    index_title = "Platform administration"

    def login(
        self, request: HttpRequest, extra_context: dict[str, Any] | None = None
    ) -> HttpResponse:
        if request.method != "POST":
            return super().login(request, extra_context)
        throttle = AdminLoginThrottle()
        if not throttle.allows(request):
            return too_many_requests(request, throttle.wait())

        response = super().login(request, extra_context)
        # A valid sign-in redirects; a rejected one re-renders the form. (request.user
        # alone is not enough: the session may already belong to someone.)
        user = resolve_user(request.user)
        if isinstance(response, HttpResponseRedirect) and user is not None:
            record(
                AuditAction.LOGIN_SUCCEEDED,
                actor=user,
                organization=user.organization,
                metadata={"channel": ADMIN_CHANNEL},
            )
        else:
            services.record_failed_login(
                str(request.POST.get("username", "")), channel=ADMIN_CHANNEL
            )
        return response

    def password_change(
        self, request: HttpRequest, extra_context: dict[str, Any] | None = None
    ) -> TemplateResponse:
        response = super().password_change(request, extra_context)
        user = resolve_user(request.user)
        if request.method == "POST" and response.status_code == 302 and user is not None:
            with transaction.atomic():
                services.revoke_all_tokens(user, SessionEndReason.PASSWORD_CHANGED)
                record(
                    AuditAction.PASSWORD_CHANGED,
                    actor=user,
                    organization=user.organization,
                    target=user,
                    metadata={"channel": ADMIN_CHANNEL},
                )
            # The token version is part of the session hash: keep this session.
            update_session_auth_hash(request, user)
        return response
