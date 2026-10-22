from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from django.core import mail
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.models import Invitation, InvitationStatus, User, hash_invitation_token
from apps.accounts.roles import Role
from apps.auditlogs.models import AuditAction, AuditLog
from tests.conftest import ClientFactory, World

pytestmark = pytest.mark.django_db

ACCEPT = "/api/v1/invitations/accept/"
STRONG = "Sturdy-Passphrase-42"


def invite(client: APIClient, email: str, role: str = "MEMBER", **extra: Any) -> Any:
    return client.post(reverse("invitation-list"), {"email": email, "role": role, **extra})


def test_invitation_lifecycle(
    world: World,
    client_for: ClientFactory,
    api_client: APIClient,
    django_capture_on_commit_callbacks: Any,
) -> None:
    with django_capture_on_commit_callbacks(execute=True):
        created = invite(client_for(world.admin_a), "New.Hire@A.test", "ORG_ADMIN")
    assert created.status_code == 201, created.content
    body = created.json()
    token = body["token"]
    assert body["email"] == "new.hire@a.test"
    assert body["status"] == "pending"
    assert body["organization"] == str(world.org_a.pk)
    assert token in body["accept_url"]

    invitation = Invitation.objects.get(pk=body["id"])
    assert invitation.token_hash == hash_invitation_token(token)
    assert token not in str(Invitation.objects.filter(pk=invitation.pk).values().get())
    assert len(mail.outbox) == 1
    assert body["accept_url"] in mail.outbox[0].body

    accepted = api_client.post(ACCEPT, {"token": token, "password": STRONG, "full_name": "New"})
    assert accepted.status_code == 201, accepted.content
    user = User.objects.get(email="new.hire@a.test")
    assert (user.organization, user.role) == (world.org_a, Role.ORG_ADMIN)
    invitation.refresh_from_db()
    assert invitation.status == InvitationStatus.ACCEPTED
    assert invitation.accepted_user == user

    # Single use.
    assert api_client.post(ACCEPT, {"token": token, "password": STRONG}).status_code == 400
    login = api_client.post(reverse("auth-login"), {"email": "new.hire@a.test", "password": STRONG})
    assert login.status_code == 200
    actions = set(AuditLog.objects.values_list("action", flat=True))
    assert {AuditAction.INVITATION_CREATED, AuditAction.INVITATION_ACCEPTED} <= actions


@pytest.mark.parametrize("state", ["expired", "revoked", "org-inactive", "unknown"])
def test_unusable_tokens_fail_generically(
    world: World, client_for: ClientFactory, api_client: APIClient, state: str
) -> None:
    token = invite(client_for(world.admin_a), "late@a.test").json()["token"]
    invitation = Invitation.objects.get(email="late@a.test")
    if state == "expired":
        Invitation.objects.filter(pk=invitation.pk).update(
            expires_at=timezone.now() - timedelta(seconds=1)
        )
    elif state == "revoked":
        client_for(world.admin_a).post(reverse("invitation-revoke", args=[invitation.pk]))
    elif state == "org-inactive":
        world.org_a.is_active = False
        world.org_a.save()
    else:
        token = "x" * 43

    response = api_client.post(ACCEPT, {"token": token, "password": STRONG})
    assert response.status_code == 400
    assert response.json() == {"token": ["This invitation is invalid or has expired."]}
    assert not User.objects.filter(email="late@a.test").exists()


def test_weak_password_keeps_invitation_pending(
    world: World, client_for: ClientFactory, api_client: APIClient
) -> None:
    token = invite(client_for(world.admin_a), "weak@a.test").json()["token"]
    response = api_client.post(ACCEPT, {"token": token, "password": "password"})
    assert response.status_code == 400
    assert "password" in response.json()
    assert Invitation.objects.get(email="weak@a.test").status == InvitationStatus.PENDING


def test_duplicate_pending_invitation_is_rejected_but_expired_is_superseded(
    world: World, client_for: ClientFactory
) -> None:
    client = client_for(world.admin_a)
    assert invite(client, "dup@a.test").status_code == 201
    assert invite(client, "dup@a.test").status_code == 400

    Invitation.objects.filter(email="dup@a.test").update(expires_at=timezone.now())
    assert invite(client, "dup@a.test").status_code == 201
    statuses = sorted(i.status for i in Invitation.objects.filter(email="dup@a.test"))
    assert statuses == [InvitationStatus.PENDING, InvitationStatus.REVOKED]


def test_existing_member_cannot_be_invited(world: World, client_for: ClientFactory) -> None:
    response = invite(client_for(world.admin_a), "member@a.test")
    assert response.status_code == 400
    assert "email" in response.json()


def test_no_cross_tenant_email_enumeration(
    world: World, client_for: ClientFactory, api_client: APIClient
) -> None:
    """Inviting an address registered in *another* tenant reveals nothing."""
    response = invite(client_for(world.admin_a), "member@b.test")
    assert response.status_code == 201
    accept = api_client.post(ACCEPT, {"token": response.json()["token"], "password": STRONG})
    assert accept.status_code == 400
    assert User.objects.get(email="member@b.test").organization == world.org_b


def test_revoke_only_pending(world: World, client_for: ClientFactory) -> None:
    client = client_for(world.admin_a)
    url = reverse("invitation-revoke", args=[world.invitation_a.pk])
    first = client.post(url)
    assert first.status_code == 200
    assert first.json()["status"] == "revoked"
    assert client.post(url).status_code == 400


def test_super_admin_must_choose_an_organization(world: World, client_for: ClientFactory) -> None:
    client = client_for(world.super_admin)
    assert invite(client, "boss@b.test").status_code == 400
    response = invite(client, "boss@b.test", "ORG_ADMIN", organization=str(world.org_b.pk))
    assert response.status_code == 201
    assert response.json()["organization"] == str(world.org_b.pk)


def test_cannot_invite_into_inactive_organization(world: World, client_for: ClientFactory) -> None:
    world.org_b.is_active = False
    world.org_b.save()
    response = invite(client_for(world.super_admin), "x@b.test", organization=str(world.org_b.pk))
    assert response.status_code == 400


def test_status_filter(world: World, client_for: ClientFactory) -> None:
    client = client_for(world.admin_a)
    invite(client, "second@a.test")
    client.post(reverse("invitation-revoke", args=[world.invitation_a.pk]))

    def emails(status: str) -> set[str]:
        response = client.get(reverse("invitation-list"), {"status": status})
        return {row["email"] for row in response.json()["results"]}

    assert emails("pending") == {"second@a.test"}
    assert emails("revoked") == {"invitee@a.test"}
    assert emails("accepted") == set()
    assert emails("expired") == set()


def test_email_failure_does_not_break_invitation(
    world: World,
    client_for: ClientFactory,
    monkeypatch: pytest.MonkeyPatch,
    django_capture_on_commit_callbacks: Any,
) -> None:
    def explode(*args: Any, **kwargs: Any) -> None:
        raise ConnectionError("SMTP down")

    monkeypatch.setattr("apps.accounts.services.send_mail", explode)
    with django_capture_on_commit_callbacks(execute=True):
        response = invite(client_for(world.admin_a), "offline@a.test")
    assert response.status_code == 201
    assert Invitation.objects.filter(email="offline@a.test").exists()
