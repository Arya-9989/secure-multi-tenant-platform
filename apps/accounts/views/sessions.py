"""The signed-in user's own sessions: see where you are signed in, end any of them."""

from __future__ import annotations

from typing import Any

from django.db import transaction
from django.utils import timezone
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import serializers, status
from rest_framework.exceptions import NotAuthenticated, NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.authentication import family_id_of
from apps.accounts.models import RefreshTokenFamily, SessionEndReason, User
from apps.auditlogs.models import AuditAction
from apps.auditlogs.services import record
from apps.common.tenancy import resolve_user


class SessionSerializer(serializers.ModelSerializer[RefreshTokenFamily]):
    current = serializers.SerializerMethodField(help_text="The session making this request.")

    class Meta:
        model = RefreshTokenFamily
        fields = (
            "id",
            "created_at",
            "last_refreshed_at",
            "expires_at",
            "ip_address",
            "user_agent",
            "current",
        )
        read_only_fields = fields

    def get_current(self, session: RefreshTokenFamily) -> bool:
        return bool(session.pk == self.context.get("current"))


def _user(request: Request) -> User:
    user = resolve_user(request.user)
    if user is None:
        raise NotAuthenticated
    return user


class SessionListView(APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        tags=["auth"],
        summary="Where you are signed in",
        description="Your live sessions, newest first. Never another user's.",
        responses=SessionSerializer(many=True),
    )
    def get(self, request: Request) -> Response:
        sessions = RefreshTokenFamily.objects.filter(user=_user(request)).live()
        token: Any = request.auth
        current = family_id_of(token) if token is not None else None
        return Response(SessionSerializer(sessions, many=True, context={"current": current}).data)


class SessionRevokeView(APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        tags=["auth"],
        summary="End one of your sessions",
        description=(
            "Its refresh and access tokens stop working at once. Another user's session ID "
            "answers 404, exactly like one that does not exist."
        ),
        request=None,
        responses={204: None, 404: OpenApiResponse(description="Not one of your sessions.")},
    )
    def post(self, request: Request, session_id: Any) -> Response:
        user = _user(request)
        with transaction.atomic():
            ended = (
                RefreshTokenFamily.objects.filter(pk=session_id, user=user)
                .live()
                .update(revoked_at=timezone.now(), revoked_reason=SessionEndReason.REVOKED)
            )
            if not ended:
                raise NotFound
            record(
                AuditAction.SESSION_REVOKED,
                actor=user,
                organization=user.organization,
                target=user,
                metadata={"session": str(session_id)},
            )
        return Response(status=status.HTTP_204_NO_CONTENT)
