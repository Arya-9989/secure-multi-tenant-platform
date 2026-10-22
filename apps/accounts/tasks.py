"""Background tasks of the accounts app (ADR 0007)."""

from __future__ import annotations

import hmac
import logging
from typing import Any

from django.conf import settings
from django.core.mail import EmailMessage
from django.tasks import TaskContext, task
from django.utils import timezone

from apps.accounts.models import EmailStatus, Invitation, InvitationStatus, hash_invitation_token
from apps.common import crypto

logger = logging.getLogger(__name__)


def _message_id(invitation: Invitation) -> str:
    # Stable per invitation link, so a retry after an unrecorded success is recognisable.
    domain = settings.DEFAULT_FROM_EMAIL.rpartition("@")[2] or "localhost"
    return f"<invitation-{invitation.pk}-{invitation.token_hash[:16]}@{domain}>"


def _max_attempts() -> int:
    tasks: dict[str, dict[str, Any]] = settings.TASKS
    return int(tasks["default"].get("OPTIONS", {}).get("max_attempts", 5))


@task(takes_context=True)
def send_invitation_email(
    context: TaskContext[..., str], invitation_id: str, sealed_token: str
) -> str:
    """Email the invitation link. Idempotent: a no-op once sent or no longer pending."""
    invitation = Invitation.objects.select_related("organization").filter(pk=invitation_id).first()
    if invitation is None:
        return "gone"
    raw_token = crypto.decrypt(sealed_token)
    if not hmac.compare_digest(hash_invitation_token(raw_token), invitation.token_hash):
        return "superseded"  # resent since: a newer task carries the current link
    if invitation.email_status == EmailStatus.SENT:
        return "already-sent"
    if invitation.status != InvitationStatus.PENDING:
        Invitation.objects.filter(pk=invitation.pk).update(email_status=EmailStatus.SKIPPED)
        return "skipped"

    from apps.accounts.services import build_accept_url  # noqa: PLC0415 - import cycle

    message = EmailMessage(
        subject=f"You have been invited to {invitation.organization.name}",
        body=(
            f"You have been invited to join {invitation.organization.name} as "
            f"{invitation.get_role_display()}.\n\n"
            f"Accept the invitation: {build_accept_url(raw_token)}\n\n"
            f"This link expires at {invitation.expires_at:%Y-%m-%d %H:%M} UTC."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[invitation.email],
        headers={"Message-ID": _message_id(invitation)},
    )
    attempt = context.attempt
    try:
        message.send(fail_silently=False)
    except Exception as exc:
        Invitation.objects.filter(pk=invitation.pk).update(
            email_attempts=attempt,
            email_last_error=f"{type(exc).__name__}: {exc}"[:200],
            email_status=EmailStatus.FAILED if attempt >= _max_attempts() else EmailStatus.QUEUED,
        )
        logger.warning("Invitation email failed (attempt %s): %s", attempt, exc)
        raise
    Invitation.objects.filter(pk=invitation.pk).update(
        email_status=EmailStatus.SENT,
        email_attempts=attempt,
        email_sent_at=timezone.now(),
        email_last_error="",
        email_message_id=_message_id(invitation),
    )
    return "sent"
