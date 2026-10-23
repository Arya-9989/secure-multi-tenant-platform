"""Second factors: enrolment, verification, recovery and admin reset (ADR 0004).

Every state change runs in a transaction with its audit record. Verifications
that must happen at most once (a TOTP time step, a recovery code, a WebAuthn
challenge) are single conditional ``UPDATE`` statements or single-use cache
entries, so concurrent requests cannot both succeed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.crypto import salted_hmac
from rest_framework.exceptions import NotFound, ValidationError
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from apps.accounts.models import SessionEndReason, User
from apps.auditlogs.models import AuditAction
from apps.auditlogs.services import record
from apps.common import crypto
from apps.mfa import totp
from apps.mfa.models import RecoveryCode, TotpDevice, WebAuthnCredential

logger = logging.getLogger(__name__)

RECOVERY_CODE_COUNT = 10
_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # 32 symbols, no 0/O or 1/I
_REGISTRATION_KEY = "mfa:webauthn-registration:{user}"
_CHALLENGE_KEY = "mfa:challenge:{digest}"
_ATTEMPTS_KEY = "mfa:challenge:{digest}:attempts"
MAX_CHALLENGE_ATTEMPTS = 5

TOTP = "totp"
WEBAUTHN = "webauthn"
RECOVERY_CODE = "recovery_code"


# ---------------------------------------------------------------- state
def has_mfa(user: User) -> bool:
    return (
        TotpDevice.objects.filter(user=user, confirmed_at__isnull=False).exists()
        or WebAuthnCredential.objects.filter(user=user).exists()
    )


def methods(user: User) -> list[str]:
    available = []
    if TotpDevice.objects.filter(user=user, confirmed_at__isnull=False).exists():
        available.append(TOTP)
    if WebAuthnCredential.objects.filter(user=user).exists():
        available.append(WEBAUTHN)
    if RecoveryCode.objects.filter(user=user, used_at__isnull=True).exists():
        available.append(RECOVERY_CODE)
    return available


def status(user: User) -> dict[str, Any]:
    device = TotpDevice.objects.filter(user=user).first()
    return {
        "enabled": has_mfa(user),
        "totp": {"confirmed": device.confirmed_at is not None} if device else None,
        "webauthn": [
            {
                "id": str(credential.pk),
                "name": credential.name,
                "created_at": credential.created_at,
                "last_used_at": credential.last_used_at,
            }
            for credential in WebAuthnCredential.objects.filter(user=user)
        ],
        "recovery_codes_remaining": RecoveryCode.objects.filter(
            user=user, used_at__isnull=True
        ).count(),
    }


def require_password(user: User, password: str) -> None:
    """Changing a factor needs the password, not just a (possibly stolen) session."""
    if not user.check_password(password):
        raise ValidationError({"password": ["Password is incorrect."]})


def _audit(action: AuditAction, user: User, **metadata: Any) -> None:
    record(action, actor=user, organization=user.organization, target=user, metadata=metadata)


# ---------------------------------------------------------------- TOTP
def begin_totp(user: User, password: str) -> dict[str, str]:
    """Create (or replace) an unconfirmed device and return its secret, shown once."""
    require_password(user, password)
    if TotpDevice.objects.filter(user=user, confirmed_at__isnull=False).exists():
        raise ValidationError({"detail": "An authenticator app is already set up."})
    secret = totp.new_secret()
    with transaction.atomic():
        TotpDevice.objects.filter(user=user).delete()
        TotpDevice.objects.create(
            user=user,
            organization_id=user.organization_id,
            secret_encrypted=crypto.encrypt(secret.hex()),
        )
    return {
        "secret": totp.encode_secret(secret),
        "otpauth_uri": totp.provisioning_uri(secret, user.email, settings.MFA_ISSUER),
    }


def confirm_totp(user: User, code: str) -> list[str]:
    """Activate the pending device with a first valid code. Returns new recovery codes
    when this is the user's first factor (else an empty list)."""
    device = TotpDevice.objects.filter(user=user, confirmed_at__isnull=True).first()
    if device is None:
        raise ValidationError({"detail": "Start the authenticator app setup first."})
    if not _accept_totp(device, code):
        raise ValidationError({"code": ["That code is not valid."]})
    with transaction.atomic():
        first_factor = not has_mfa(user)
        device.confirmed_at = timezone.now()
        device.save(update_fields=["confirmed_at"])
        _audit(AuditAction.MFA_TOTP_ENABLED, user)
        return _new_recovery_codes(user) if first_factor else []


def disable_totp(user: User, password: str) -> None:
    require_password(user, password)
    with transaction.atomic():
        deleted, _ = TotpDevice.objects.filter(user=user).delete()
        if not deleted:
            raise ValidationError({"detail": "No authenticator app is set up."})
        _drop_recovery_codes_if_last_factor(user)
        _audit(AuditAction.MFA_TOTP_DISABLED, user)


def _accept_totp(device: TotpDevice, code: str) -> bool:
    """Accept ``code`` once: its time step must be newer than any accepted before."""
    secret = bytes.fromhex(crypto.decrypt(device.secret_encrypted))
    step = totp.matching_step(secret, code.strip().replace(" ", ""), time.time())
    if step is None:
        return False
    return bool(
        TotpDevice.objects.filter(pk=device.pk, last_used_step__lt=step).update(last_used_step=step)
    )


def verify_totp(user: User, code: str) -> bool:
    device = TotpDevice.objects.filter(user=user, confirmed_at__isnull=False).first()
    return device is not None and _accept_totp(device, code)


# ---------------------------------------------------------------- recovery codes
def _hash_recovery_code(code: str) -> str:
    normalized = code.upper().replace("-", "").replace(" ", "")
    return salted_hmac("apps.mfa.recovery-code", normalized, algorithm="sha256").hexdigest()


def _new_recovery_codes(user: User) -> list[str]:
    codes = [
        "-".join("".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(4)) for _ in range(3))
        for _ in range(RECOVERY_CODE_COUNT)
    ]
    RecoveryCode.objects.filter(user=user).delete()
    RecoveryCode.objects.bulk_create(
        RecoveryCode(
            user=user, organization_id=user.organization_id, code_hash=_hash_recovery_code(c)
        )
        for c in codes
    )
    return codes


def regenerate_recovery_codes(user: User, password: str) -> list[str]:
    require_password(user, password)
    if not has_mfa(user):
        raise ValidationError({"detail": "Set up a second factor first."})
    with transaction.atomic():
        codes = _new_recovery_codes(user)
        _audit(AuditAction.MFA_RECOVERY_CODES_GENERATED, user)
    return codes


def use_recovery_code(user: User, code: str) -> bool:
    return bool(
        RecoveryCode.objects.filter(
            user=user, code_hash=_hash_recovery_code(code), used_at__isnull=True
        ).update(used_at=timezone.now())
    )


def _drop_recovery_codes_if_last_factor(user: User) -> None:
    if not has_mfa(user):
        RecoveryCode.objects.filter(user=user).delete()


# ---------------------------------------------------------------- WebAuthn
def _descriptors(user: User) -> list[PublicKeyCredentialDescriptor]:
    descriptors = []
    for credential in WebAuthnCredential.objects.filter(user=user):
        transports = []
        for value in credential.transports:
            try:
                transports.append(AuthenticatorTransport(value))
            except ValueError:
                continue
        descriptors.append(
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(credential.credential_id), transports=transports or None
            )
        )
    return descriptors


def begin_registration(user: User, password: str) -> dict[str, Any]:
    require_password(user, password)
    options = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_id=user.pk.bytes,
        user_name=user.email,
        user_display_name=user.full_name or user.email,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        exclude_credentials=_descriptors(user),
    )
    cache.set(
        _REGISTRATION_KEY.format(user=user.pk),
        bytes_to_base64url(options.challenge),
        timeout=settings.MFA_CHALLENGE_TTL_SECONDS,
    )
    result: dict[str, Any] = json.loads(options_to_json(options))
    return result


def complete_registration(user: User, credential: dict[str, Any], name: str) -> list[str]:
    """Store the new credential. Returns recovery codes if this is the first factor."""
    key = _REGISTRATION_KEY.format(user=user.pk)
    challenge = cache.get(key)
    cache.delete(key)  # single use, whatever the outcome
    if not challenge:
        raise ValidationError({"detail": "Start the security key registration first."})
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ORIGINS,
        )
    except (InvalidRegistrationResponse, ValueError, KeyError, TypeError) as exc:
        logger.info("WebAuthn registration rejected: %s", exc)
        raise ValidationError({"credential": ["The security key response is not valid."]}) from exc
    transports = credential.get("response", {}).get("transports") or []
    try:
        with transaction.atomic():
            first_factor = not has_mfa(user)
            WebAuthnCredential.objects.create(
                user=user,
                organization_id=user.organization_id,
                name=name,
                credential_id=bytes_to_base64url(verified.credential_id),
                public_key=verified.credential_public_key,
                sign_count=verified.sign_count,
                transports=[str(t) for t in transports if isinstance(t, str)][:8],
                aaguid=verified.aaguid,
            )
            _audit(AuditAction.MFA_WEBAUTHN_ADDED, user, name=name)
            return _new_recovery_codes(user) if first_factor else []
    except IntegrityError as exc:  # the same authenticator, registered before
        raise ValidationError({"credential": ["This security key is already registered."]}) from exc


def remove_credential(user: User, credential_id: uuid.UUID, password: str) -> None:
    credential = WebAuthnCredential.objects.filter(pk=credential_id, user=user).first()
    if credential is None:  # someone else's, or none: indistinguishable
        raise NotFound
    require_password(user, password)
    with transaction.atomic():
        credential.delete()
        _drop_recovery_codes_if_last_factor(user)
        _audit(AuditAction.MFA_WEBAUTHN_REMOVED, user, name=credential.name)


def begin_authentication(user: User) -> tuple[dict[str, Any], str]:
    options = generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        allow_credentials=_descriptors(user),
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    result: dict[str, Any] = json.loads(options_to_json(options))
    return result, bytes_to_base64url(options.challenge)


def verify_webauthn(user: User, credential: dict[str, Any], challenge: str) -> bool:
    raw_id = credential.get("rawId") or credential.get("id")
    stored = WebAuthnCredential.objects.filter(user=user, credential_id=str(raw_id)).first()
    if stored is None:
        return False
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ORIGINS,
            credential_public_key=bytes(stored.public_key),
            credential_current_sign_count=stored.sign_count,
        )
    except (InvalidAuthenticationResponse, ValueError, KeyError, TypeError) as exc:
        logger.info("WebAuthn assertion rejected: %s", exc)
        return False
    # Conditional on the count read above, so two uses of one count cannot both pass.
    return bool(
        WebAuthnCredential.objects.filter(pk=stored.pk, sign_count=stored.sign_count).update(
            sign_count=verified.new_sign_count, last_used_at=timezone.now()
        )
    )


# ---------------------------------------------------------------- admin reset
def reset(*, actor: User, target: User) -> None:
    """An admin removes a member's factors (lost device). Ends their sessions too."""
    from apps.accounts.services import (  # noqa: PLC0415 - import cycle
        check_can_administer,
        revoke_all_tokens,
    )

    check_can_administer(actor, target)  # same tenant, not yourself, not a super admin
    with transaction.atomic():
        TotpDevice.objects.filter(user=target).delete()
        WebAuthnCredential.objects.filter(user=target).delete()
        RecoveryCode.objects.filter(user=target).delete()
        revoke_all_tokens(target, SessionEndReason.MFA_RESET)
        record(
            AuditAction.MFA_RESET,
            actor=actor,
            organization=target.organization,
            target=target,
        )


# ---------------------------------------------------------------- sign-in challenges
@dataclass(frozen=True, slots=True)
class Challenge:
    token: str
    user_id: uuid.UUID
    webauthn_challenge: str | None


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_challenge(user: User) -> str:
    """After a correct password: a short-lived token for the second step."""
    token = secrets.token_urlsafe(32)
    ttl: int = settings.MFA_CHALLENGE_TTL_SECONDS
    cache.set(_CHALLENGE_KEY.format(digest=_digest(token)), {"user": str(user.pk)}, timeout=ttl)
    cache.set(_ATTEMPTS_KEY.format(digest=_digest(token)), 0, timeout=ttl)
    return token


def load_challenge(token: str) -> Challenge | None:
    data = cache.get(_CHALLENGE_KEY.format(digest=_digest(token))) if token else None
    if not isinstance(data, dict):
        return None
    return Challenge(token, uuid.UUID(data["user"]), data.get("webauthn"))


def attach_webauthn_challenge(challenge: Challenge, webauthn_challenge: str) -> None:
    key = _CHALLENGE_KEY.format(digest=_digest(challenge.token))
    data = {"user": str(challenge.user_id), "webauthn": webauthn_challenge}
    cache.set(key, data, timeout=settings.MFA_CHALLENGE_TTL_SECONDS)


def spend_attempt(challenge: Challenge) -> bool:
    """Count one second-factor attempt; ``False`` (and the challenge gone) once over."""
    digest = _digest(challenge.token)
    try:
        attempts = int(cache.incr(_ATTEMPTS_KEY.format(digest=digest)))
    except ValueError:
        return False
    if attempts > MAX_CHALLENGE_ATTEMPTS:
        discard(challenge)
        return False
    return True


def discard(challenge: Challenge) -> None:
    digest = _digest(challenge.token)
    cache.delete_many([_CHALLENGE_KEY.format(digest=digest), _ATTEMPTS_KEY.format(digest=digest)])
