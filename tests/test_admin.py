"""The Django admin: a second way in for super admins, held to the API's standards.

It must be throttled and audited like the API login, must not undo revocations or
leak live credentials, must route tenant changes through the audited services, and
must work under the same strict Content Security Policy as every other page.
"""

from __future__ import annotations

import re
from typing import Any, cast

import pytest
from django.conf import settings
from django.contrib import admin
from django.http import HttpRequest
from django.test import Client
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

from apps.auditlogs.models import AuditAction, AuditLog
from apps.organizations.models import Organization
from tests.conftest import PASSWORD, World

pytestmark = pytest.mark.django_db

LOGIN = "/api/v1/auth/login/"
NEW_PASSWORD = "A-Different-Passphrase-77"


def _auth_limit() -> int:
    rates = cast(dict[str, Any], settings.REST_FRAMEWORK)["DEFAULT_THROTTLE_RATES"]
    return int(rates["auth"].split("/")[0])


def _api_session(email: str) -> dict[str, str]:
    response = APIClient().post(LOGIN, {"email": email, "password": PASSWORD})
    assert response.status_code == 200
    return cast(dict[str, str], response.json())


def _api_me(access: str) -> int:
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
    return client.get("/api/v1/auth/me/").status_code


@pytest.fixture
def operator(world: World, client: Client) -> Client:
    client.force_login(world.super_admin)
    return client


# ---------------------------------------------------------------- sign-in
def test_admin_login_is_throttled_like_the_api(world: World, client: Client) -> None:
    url = reverse("admin:login")
    for _ in range(_auth_limit()):
        response = client.post(url, {"username": "root@platform.test", "password": "wrong"})
        assert response.status_code == 200  # the form, redisplayed with an error

    response = client.post(url, {"username": "root@platform.test", "password": PASSWORD})
    assert response.status_code == 429
    assert "Retry-After" in response.headers
    assert "_auth_user_id" not in client.session
    assert client.get(url).status_code == 200, "only sign-in attempts are counted"


def test_admin_sign_ins_are_audited(world: World, client: Client) -> None:
    url = reverse("admin:login")
    client.post(url, {"username": "Root@Platform.test", "password": "wrong"})
    failed = AuditLog.objects.get(action=AuditAction.LOGIN_FAILED)
    assert failed.metadata == {"email": "root@platform.test", "channel": "admin"}
    assert failed.actor is None
    assert failed.organization is None

    assert (
        client.post(url, {"username": "root@platform.test", "password": PASSWORD}).status_code
        == 302
    )
    succeeded = AuditLog.objects.get(action=AuditAction.LOGIN_SUCCEEDED)
    assert succeeded.actor == world.super_admin
    assert succeeded.metadata == {"channel": "admin"}


def test_a_failed_sign_in_counts_as_failed_even_with_a_live_session(
    world: World, operator: Client
) -> None:
    """Success is judged by the sign-in itself, not by who the session already belongs to."""
    response = operator.post(
        reverse("admin:login"), {"username": "root@platform.test", "password": "wrong"}
    )
    assert response.status_code == 200
    assert AuditLog.objects.filter(action=AuditAction.LOGIN_FAILED).count() == 1
    assert not AuditLog.objects.filter(action=AuditAction.LOGIN_SUCCEEDED).exists()


# ---------------------------------------------------------------- sessions
def test_logging_out_everywhere_ends_admin_sessions_too(world: World, operator: Client) -> None:
    assert operator.get(reverse("admin:index")).status_code == 200
    access = _api_session("root@platform.test")["access"]
    api = APIClient()
    api.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
    assert api.post("/api/v1/auth/logout-all/").status_code == 204

    response = operator.get(reverse("admin:index"))
    assert response.status_code == 302
    assert response["Location"].startswith(reverse("admin:login"))


def test_admin_password_change_revokes_api_sessions_and_is_audited(
    world: World, operator: Client
) -> None:
    access = _api_session("root@platform.test")["access"]
    response = operator.post(
        reverse("admin:password_change"),
        {"old_password": PASSWORD, "new_password1": NEW_PASSWORD, "new_password2": NEW_PASSWORD},
    )
    assert response.status_code == 302

    assert _api_me(access) == 401
    event = AuditLog.objects.get(action=AuditAction.PASSWORD_CHANGED)
    assert event.actor == world.super_admin
    assert event.metadata == {"channel": "admin"}
    assert operator.get(reverse("admin:index")).status_code == 200, "this session survives"


# ---------------------------------------------------------------- credentials
def test_admin_never_shows_raw_refresh_tokens(world: World, operator: Client) -> None:
    """Rotated refresh tokens are stored verbatim; the admin must not display them."""
    first = _api_session("member@a.test")["refresh"]
    rotated = APIClient().post("/api/v1/auth/refresh/", {"refresh": first})
    refresh = rotated.json()["refresh"]
    live = OutstandingToken.objects.get(token=refresh)
    blacklisted = BlacklistedToken.objects.get(token__user=world.member_a)
    outstanding = live

    pages = [
        reverse("admin:token_blacklist_outstandingtoken_changelist"),
        reverse("admin:token_blacklist_outstandingtoken_change", args=[outstanding.pk]),
        reverse("admin:token_blacklist_blacklistedtoken_changelist"),
        reverse("admin:token_blacklist_blacklistedtoken_change", args=[blacklisted.pk]),
    ]
    for page in pages:
        response = operator.get(page)
        assert response.status_code == 200, page
        html = response.content.decode()
        assert refresh not in html, page
        assert refresh.split(".")[1] not in html, f"{page} shows the token payload"


def test_admin_cannot_unrevoke_a_token(world: World, operator: Client) -> None:
    _api_session("member@a.test")
    blacklisted = BlacklistedToken.objects.create(
        token=OutstandingToken.objects.get(user=world.member_a)
    )
    delete = reverse("admin:token_blacklist_blacklistedtoken_delete", args=[blacklisted.pk])
    assert operator.get(delete).status_code == 403
    operator.post(delete, {"post": "yes"})
    changelist = reverse("admin:token_blacklist_blacklistedtoken_changelist")
    operator.post(changelist, {"action": "delete_selected", "_selected_action": [blacklisted.pk]})
    assert BlacklistedToken.objects.filter(pk=blacklisted.pk).exists()


# ---------------------------------------------------------------- tenants
def test_organization_changes_in_the_admin_go_through_the_audited_service(
    world: World, operator: Client
) -> None:
    member_session = _api_session("member@a.test")
    change = reverse("admin:organizations_organization_change", args=[world.org_a.pk])
    response = operator.post(change, {"name": "Acme Corp", "slug": "acme"})  # unticks is_active
    assert response.status_code == 302

    world.org_a.refresh_from_db()
    assert world.org_a.is_active is False
    event = AuditLog.objects.get(action=AuditAction.ORGANIZATION_UPDATED)
    assert event.actor == world.super_admin
    assert event.metadata == {"changes": {"is_active": {"from": True, "to": False}}}
    assert _api_me(member_session["access"]) == 401

    add = reverse("admin:organizations_organization_add")
    response = operator.post(add, {"name": "Initech", "slug": "initech", "is_active": "on"})
    assert response.status_code == 302
    created = AuditLog.objects.get(action=AuditAction.ORGANIZATION_CREATED)
    assert created.actor == world.super_admin
    assert created.metadata == {"name": "Initech", "slug": "initech"}


def test_organizations_cannot_be_deleted_from_the_admin(world: World, operator: Client) -> None:
    empty = Organization.objects.create(name="Empty Co", slug="empty")
    delete = reverse("admin:organizations_organization_delete", args=[empty.pk])
    assert operator.get(delete).status_code == 403
    operator.post(delete, {"post": "yes"})
    assert Organization.objects.filter(pk=empty.pk).exists()


# ---------------------------------------------------------------- CSP
def _admin_pages(world: World) -> list[str]:
    _api_session("member@a.test")
    objects: dict[type[Any], Any] = {
        model: model._default_manager.first() for model in admin.site._registry
    }
    pages = [reverse("admin:index"), reverse("admin:password_change")]
    for model, model_admin in admin.site._registry.items():
        info = (model._meta.app_label, model._meta.model_name)
        pages.append(reverse("admin:{}_{}_changelist".format(*info)))
        pages.append(reverse("admin:app_list", args=[model._meta.app_label]))
        if model_admin.has_add_permission(cast(HttpRequest, _FakeRequest(world))):
            pages.append(reverse("admin:{}_{}_add".format(*info)))
        if objects[model] is not None:
            pages.append(reverse("admin:{}_{}_change".format(*info), args=[objects[model].pk]))
            pages.append(reverse("admin:{}_{}_history".format(*info), args=[objects[model].pk]))
    return sorted(set(pages))


class _FakeRequest:
    def __init__(self, world: World) -> None:
        self.user = world.super_admin


def test_every_admin_page_works_under_the_strict_csp(world: World, operator: Client) -> None:
    pages = _admin_pages(world)
    assert len(pages) > 20
    for page in pages:
        response = operator.get(page)
        assert response.status_code == 200, page
        policy = response["Content-Security-Policy"]
        assert "script-src 'self';" in policy, page
        assert "unsafe-inline" not in policy, page
        html = response.content.decode()
        inline = re.findall(r"<script(?![^>]*\bsrc=)(?![^>]*application/json)[^>]*>", html)
        assert not inline, f"{page}: inline script {inline}"
        assert not re.search(r"<[a-z][^>]*\sstyle=", html), f"{page}: inline style attribute"
        assert not re.search(r"<[a-z][^>]*\son[a-z]+=", html), f"{page}: inline event handler"
