"""Forgotten passwords: a reset link by email, with no account enumeration.

* Asking for a link always answers the same way, whether or not the email
  belongs to an account. The request only queues a task (with the email
  encrypted); the task looks the account up and sends the link if there is one,
  so neither the answer nor its timing depends on the account existing. At most
  ``PASSWORD_RESET_MAX_PER_HOUR`` links are sent per address per hour.
* The link carries Django's password-reset token (HMAC over the account's
  password hash, last login, token version and a timestamp): it expires after
  ``PASSWORD_RESET_TIMEOUT`` seconds and stops working once used, once the
  password changes, and after a sign-out everywhere.
* Resetting ends every session and is audited. A second factor, if enabled,
  is still required at the next sign-in.
"""

from __future__ import annotations

import uuid
from typing import Any

from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.cache import cache
from django.db import transaction
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework.exceptions import ValidationError

from apps.accounts import login_throttle
from apps.accounts.authentication import user_can_authenticate
from apps.accounts.models import SessionEndReason, User, normalize_email
from apps.accounts.scopes import scope_for_account
from apps.auditlogs.models import AuditAction
from apps.auditlogs.services import record
from apps.common import crypto, rls

INVALID_LINK = "This reset link is invalid or has expired."


class ResetTokenGenerator(PasswordResetTokenGenerator):
    key_salt = "apps.accounts.password_reset.ResetTokenGenerator"

    def _make_hash_value(self, user: Any, timestamp: int) -> str:
        # Signing out everywhere (token_version) also kills pending reset links.
        return f"{super()._make_hash_value(user, timestamp)}:{user.token_version}"


tokens = ResetTokenGenerator()


def request_reset(email: str) -> None:
    """Queue the lookup and the email; answer nothing about the account."""
    from apps.accounts.tasks import send_password_reset_email  # noqa: PLC0415 - import cycle

    email = normalize_email(email)
    key = f"password-reset:{login_throttle.account_key(email)}"
    cache.add(key, 0, timeout=3600)
    if int(cache.incr(key)) > settings.PASSWORD_RESET_MAX_PER_HOUR:
        return  # same answer; no more mail to that address this hour
    with rls.platform_scope():  # the task decides whether there is an account at all
        send_password_reset_email.enqueue(crypto.encrypt(email))


def reset_link(user: User) -> str:
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    url: str = settings.FRONTEND_PASSWORD_RESET_URL
    return url.format(uid=uid, token=tokens.make_token(user))


def confirm_reset(*, uid: str, token: str, new_password: str) -> User:
    from apps.accounts.services import _validate_password, revoke_all_tokens  # noqa: PLC0415

    invalid = ValidationError({"token": [INVALID_LINK]})
    try:
        user_id = uuid.UUID(force_str(urlsafe_base64_decode(uid)))
    except (TypeError, ValueError, UnicodeDecodeError) as exc:
        raise invalid from exc
    scope = scope_for_account(user_id=user_id)
    with rls.scope(scope):
        user = User.objects.select_related("organization").filter(pk=user_id).first()
        if user is None or not user_can_authenticate(user) or not tokens.check_token(user, token):
            raise invalid
        _validate_password(new_password, user)
        with transaction.atomic():
            user.set_password(new_password)
            user.save(update_fields=["password", "updated_at"])
            revoke_all_tokens(user, SessionEndReason.PASSWORD_RESET)
            record(
                AuditAction.PASSWORD_RESET,
                actor=user,
                organization=user.organization,
                target=user,
            )
    login_throttle.clear(user.email)  # they proved control of the mailbox
    return user
