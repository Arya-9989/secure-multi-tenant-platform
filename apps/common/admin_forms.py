"""The admin sign-in form, with the second factor (ADR 0004).

The admin is a second way in for super admins, so an account with MFA must
pass it here too: a TOTP code or a recovery code, checked after the password.
(WebAuthn needs a browser ceremony the admin's form does not run; such an
account signs in here with a recovery code.)
"""

from __future__ import annotations

from typing import Any

from django import forms
from django.contrib.admin.forms import AdminAuthenticationForm
from django.core.exceptions import ValidationError

from apps.mfa import services as mfa


class MfaAdminAuthenticationForm(AdminAuthenticationForm):
    otp = forms.CharField(
        label="Authentication code (if you use one)",
        required=False,
        max_length=32,
        widget=forms.TextInput(
            attrs={"autocomplete": "one-time-code", "inputmode": "numeric", "spellcheck": "false"}
        ),
    )

    error_messages = {
        **AdminAuthenticationForm.error_messages,
        "mfa_required": (
            "This account uses multi-factor authentication. Enter a code from your "
            "authenticator app, or one of your recovery codes."
        ),
    }

    def clean(self) -> dict[str, Any]:
        cleaned: dict[str, Any] = super().clean()
        user = self.get_user()
        if user is not None and mfa.has_mfa(user):
            code = str(cleaned.get("otp") or "").strip()
            accepted = bool(code) and (
                mfa.verify_totp(user, code) if code.isdigit() else mfa.use_recovery_code(user, code)
            )
            if not accepted:
                raise ValidationError(self.error_messages["mfa_required"], code="mfa_required")
        return cleaned
