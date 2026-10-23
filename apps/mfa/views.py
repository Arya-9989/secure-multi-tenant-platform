"""MFA endpoints: enrolment for the signed-in user, and the second sign-in step."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from drf_spectacular.utils import OpenApiResponse, extend_schema, inline_serializer
from rest_framework import serializers, status
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated, Throttled
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import BaseThrottle
from rest_framework.views import APIView

from apps.accounts import login_throttle, signin
from apps.accounts.authentication import user_can_authenticate
from apps.accounts.models import User
from apps.accounts.scopes import scope_for_account
from apps.accounts.serializers.auth import TokenPairResponseSerializer
from apps.auditlogs.models import AuditAction
from apps.auditlogs.services import record
from apps.common import rls
from apps.common.serializers import StrictSerializer
from apps.common.tenancy import resolve_user
from apps.common.throttling import ClientScopedRateThrottle
from apps.mfa import services as mfa

INVALID_SECOND_FACTOR = "Invalid or expired code."


class _CredentialThrottled:
    throttle_classes: Sequence[type[BaseThrottle]] = (ClientScopedRateThrottle,)
    throttle_scope = "auth"


def _user(request: Request) -> User:
    user = resolve_user(request.user)
    if user is None:
        raise NotAuthenticated
    return user


class PasswordSerializer(StrictSerializer):
    password = serializers.CharField(style={"input_type": "password"}, trim_whitespace=False)


class CodeSerializer(StrictSerializer):
    code = serializers.CharField(max_length=32)


class RegistrationSerializer(StrictSerializer):
    credential = serializers.DictField(help_text="The `PublicKeyCredential` from the browser.")
    name = serializers.CharField(max_length=64, default="Security key")


class SecondStepSerializer(StrictSerializer):
    mfa_token = serializers.CharField(max_length=128)
    code = serializers.CharField(max_length=32, help_text="A TOTP code or a recovery code.")


class WebAuthnBeginSerializer(StrictSerializer):
    mfa_token = serializers.CharField(max_length=128)


class WebAuthnCompleteSerializer(StrictSerializer):
    mfa_token = serializers.CharField(max_length=128)
    credential = serializers.DictField(help_text="The `PublicKeyCredential` from the browser.")


_status = inline_serializer(
    "MfaStatus",
    fields={
        "enabled": serializers.BooleanField(),
        "totp": inline_serializer(
            "MfaTotpStatus", fields={"confirmed": serializers.BooleanField()}, allow_null=True
        ),
        "webauthn": inline_serializer(
            "MfaWebAuthnCredential",
            many=True,
            fields={
                "id": serializers.UUIDField(),
                "name": serializers.CharField(),
                "created_at": serializers.DateTimeField(),
                "last_used_at": serializers.DateTimeField(allow_null=True),
            },
        ),
        "recovery_codes_remaining": serializers.IntegerField(),
    },
)
_codes = inline_serializer(
    "RecoveryCodes",
    fields={
        "recovery_codes": serializers.ListField(
            child=serializers.CharField(), help_text="Shown once. Store them somewhere safe."
        )
    },
)
_options = OpenApiResponse(
    description="`PublicKeyCredential*Options` for `navigator.credentials` (WebAuthn JSON)."
)


# ---------------------------------------------------------------- the signed-in user
class MfaStatusView(APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(tags=["mfa"], summary="Your second factors", responses=_status)
    def get(self, request: Request) -> Response:
        return Response(mfa.status(_user(request)))


class TotpSetupView(_CredentialThrottled, APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        tags=["mfa"],
        summary="Start setting up an authenticator app",
        description="Needs your password. Returns the secret and `otpauth://` URI once.",
        request=PasswordSerializer,
        responses=inline_serializer(
            "TotpSetup",
            fields={"secret": serializers.CharField(), "otpauth_uri": serializers.CharField()},
        ),
    )
    def post(self, request: Request) -> Response:
        serializer = PasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(mfa.begin_totp(_user(request), serializer.validated_data["password"]))


class TotpConfirmView(_CredentialThrottled, APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        tags=["mfa"],
        summary="Confirm the authenticator app with a first code",
        description="Recovery codes are returned once, when this is your first factor.",
        request=CodeSerializer,
        responses=_codes,
    )
    def post(self, request: Request) -> Response:
        serializer = CodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        codes = mfa.confirm_totp(_user(request), serializer.validated_data["code"])
        return Response({"recovery_codes": codes})


class TotpDisableView(_CredentialThrottled, APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        tags=["mfa"],
        summary="Remove the authenticator app",
        request=PasswordSerializer,
        responses={204: None},
    )
    def post(self, request: Request) -> Response:
        serializer = PasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        mfa.disable_totp(_user(request), serializer.validated_data["password"])
        return Response(status=status.HTTP_204_NO_CONTENT)


class RecoveryCodesView(_CredentialThrottled, APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        tags=["mfa"],
        summary="Replace your recovery codes",
        description="Needs your password. Every earlier code stops working.",
        request=PasswordSerializer,
        responses=_codes,
    )
    def post(self, request: Request) -> Response:
        serializer = PasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        codes = mfa.regenerate_recovery_codes(_user(request), serializer.validated_data["password"])
        return Response({"recovery_codes": codes})


class WebAuthnRegisterBeginView(_CredentialThrottled, APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        tags=["mfa"],
        summary="Start registering a security key",
        request=PasswordSerializer,
        responses={200: _options},
    )
    def post(self, request: Request) -> Response:
        serializer = PasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            mfa.begin_registration(_user(request), serializer.validated_data["password"])
        )


class WebAuthnRegisterCompleteView(_CredentialThrottled, APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        tags=["mfa"],
        summary="Finish registering a security key",
        description="Recovery codes are returned once, when this is your first factor.",
        request=RegistrationSerializer,
        responses={201: _codes},
    )
    def post(self, request: Request) -> Response:
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        codes = mfa.complete_registration(
            _user(request),
            serializer.validated_data["credential"],
            serializer.validated_data["name"],
        )
        return Response({"recovery_codes": codes}, status=status.HTTP_201_CREATED)


class WebAuthnRemoveView(_CredentialThrottled, APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        tags=["mfa"],
        summary="Remove one of your security keys",
        description="Another user's key ID answers 404, like an unknown one.",
        request=PasswordSerializer,
        responses={204: None, 404: OpenApiResponse(description="Not one of your keys.")},
    )
    def post(self, request: Request, credential_id: Any) -> Response:
        serializer = PasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        mfa.remove_credential(_user(request), credential_id, serializer.validated_data["password"])
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------- the second sign-in step
class _SecondStep(_CredentialThrottled, APIView):
    authentication_classes = ()
    permission_classes = (AllowAny,)

    def get_authenticate_header(self, request: Request) -> str:
        return 'Bearer realm="api"'  # so a refusal is 401, as at /auth/login/

    def start(
        self, request: Request, token: str
    ) -> tuple[mfa.Challenge, User, login_throttle.Decision]:
        challenge = mfa.load_challenge(token)
        if challenge is None:
            raise AuthenticationFailed(INVALID_SECOND_FACTOR)
        scope = scope_for_account(user_id=challenge.user_id)
        rls.bind(scope)
        user = User.objects.select_related("organization").filter(pk=challenge.user_id).first()
        if user is None or not user_can_authenticate(user):
            mfa.discard(challenge)
            raise AuthenticationFailed(INVALID_SECOND_FACTOR)
        # The same bucket as the password (ADR 0003): the password alone buys nothing.
        decision = login_throttle.check(user.email, login_throttle.device_token_from(request))
        if not decision.allowed:
            raise Throttled(wait=decision.retry_after)
        if not mfa.spend_attempt(challenge):
            raise AuthenticationFailed(INVALID_SECOND_FACTOR)
        return challenge, user, decision

    def fail(self, user: User, method: str) -> None:
        record(
            AuditAction.MFA_FAILED,
            organization=user.organization,
            target=user,
            metadata={"method": method},
        )
        raise AuthenticationFailed(INVALID_SECOND_FACTOR)

    def succeed(
        self,
        request: Request,
        challenge: mfa.Challenge,
        user: User,
        decision: login_throttle.Decision,
        method: str,
    ) -> Response:
        mfa.discard(challenge)
        return signin.complete(request, user, decision=decision, metadata={"mfa": method})


class MfaVerifyView(_SecondStep):
    @extend_schema(
        tags=["auth"],
        summary="Second sign-in step: a TOTP or recovery code",
        description=(
            "Send the `mfa_token` from `POST /auth/login/` with a code from your "
            "authenticator app or one of your recovery codes. Five attempts per token; "
            "failures also count against the account's sign-in throttle."
        ),
        request=SecondStepSerializer,
        responses={200: TokenPairResponseSerializer, 401: OpenApiResponse(description="Invalid.")},
        auth=[],
    )
    def post(self, request: Request) -> Response:
        serializer = SecondStepSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        challenge, user, decision = self.start(request, serializer.validated_data["mfa_token"])
        code = serializer.validated_data["code"].strip()
        if code.isdigit():
            if mfa.verify_totp(user, code):
                return self.succeed(request, challenge, user, decision, mfa.TOTP)
            self.fail(user, mfa.TOTP)
        if mfa.use_recovery_code(user, code):
            return self.succeed(request, challenge, user, decision, mfa.RECOVERY_CODE)
        self.fail(user, mfa.RECOVERY_CODE)
        raise AssertionError  # pragma: no cover - fail() raises


class WebAuthnBeginView(_SecondStep):
    @extend_schema(
        tags=["auth"],
        summary="Second sign-in step: ask for a security key",
        request=WebAuthnBeginSerializer,
        responses={200: _options},
        auth=[],
    )
    def post(self, request: Request) -> Response:
        serializer = WebAuthnBeginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        challenge = mfa.load_challenge(serializer.validated_data["mfa_token"])
        if challenge is None:
            raise AuthenticationFailed(INVALID_SECOND_FACTOR)
        rls.bind(scope_for_account(user_id=challenge.user_id))
        user = User.objects.filter(pk=challenge.user_id).first()
        if user is None:
            raise AuthenticationFailed(INVALID_SECOND_FACTOR)
        options, webauthn_challenge = mfa.begin_authentication(user)
        mfa.attach_webauthn_challenge(challenge, webauthn_challenge)
        return Response(options)


class WebAuthnCompleteView(_SecondStep):
    @extend_schema(
        tags=["auth"],
        summary="Second sign-in step: the security key's answer",
        request=WebAuthnCompleteSerializer,
        responses={200: TokenPairResponseSerializer, 401: OpenApiResponse(description="Invalid.")},
        auth=[],
    )
    def post(self, request: Request) -> Response:
        serializer = WebAuthnCompleteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        challenge, user, decision = self.start(request, serializer.validated_data["mfa_token"])
        webauthn_challenge = challenge.webauthn_challenge
        # Each WebAuthn challenge is answered once, right or wrong.
        mfa.attach_webauthn_challenge(challenge, "")
        if webauthn_challenge and mfa.verify_webauthn(
            user, serializer.validated_data["credential"], webauthn_challenge
        ):
            return self.succeed(request, challenge, user, decision, mfa.WEBAUTHN)
        self.fail(user, mfa.WEBAUTHN)
        raise AssertionError  # pragma: no cover - fail() raises
