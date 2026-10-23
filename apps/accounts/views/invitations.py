from __future__ import annotations

import django_filters
from django.db.models import QuerySet
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import mixins, status
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts import services
from apps.accounts.models import Invitation, InvitationStatus
from apps.accounts.roles import ASSIGNABLE_ROLE_CHOICES, ApiScope, Perm
from apps.accounts.serializers.invitations import (
    AcceptInvitationSerializer,
    InvitationCreatedSerializer,
    InvitationCreateSerializer,
    InvitationSerializer,
)
from apps.accounts.serializers.users import UserSerializer
from apps.common.throttling import ClientScopedRateThrottle
from apps.common.views import TenantScopedViewSet


class InvitationFilter(django_filters.FilterSet):
    status = django_filters.ChoiceFilter(
        choices=[(s.value, s.value) for s in InvitationStatus], method="filter_status"
    )
    role = django_filters.ChoiceFilter(choices=ASSIGNABLE_ROLE_CHOICES)
    email = django_filters.CharFilter(lookup_expr="iexact")
    organization = django_filters.UUIDFilter(field_name="organization_id")

    class Meta:
        model = Invitation
        fields = ("status", "role", "email", "organization")

    def filter_status(
        self, queryset: QuerySet[Invitation], name: str, value: str
    ) -> QuerySet[Invitation]:
        return Invitation.objects.with_status(InvitationStatus(value)).filter(
            pk__in=queryset.values("pk")
        )


@extend_schema_view(
    list=extend_schema(summary="List invitations"),
    retrieve=extend_schema(summary="Retrieve an invitation"),
)
@extend_schema(tags=["invitations"])
class InvitationViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    TenantScopedViewSet[Invitation],
):
    queryset = Invitation.objects.select_related("organization", "invited_by")
    serializer_class = InvitationSerializer
    filterset_class = InvitationFilter
    ordering_fields = ("created_at", "expires_at", "email")
    http_method_names = ("get", "post", "head", "options")
    required_permissions = {
        "list": Perm.INVITATION_MANAGE,
        "retrieve": Perm.INVITATION_MANAGE,
        "create": Perm.INVITATION_MANAGE,
        "revoke": Perm.INVITATION_MANAGE,
        "resend": Perm.INVITATION_MANAGE,
    }
    api_key_scopes = {"list": ApiScope.INVITATIONS_READ, "retrieve": ApiScope.INVITATIONS_READ}

    @extend_schema(
        summary="Invite someone to an organization",
        description=(
            "Creates a single-use invitation that expires after `INVITATION_TTL_HOURS`. "
            "The raw token is returned **once**; only its SHA-256 digest is stored. The "
            "email is sent by a background worker with retries; follow it in "
            "`email_status`. Org admins can only invite into their own organization."
        ),
        request=InvitationCreateSerializer,
        responses={201: InvitationCreatedSerializer},
    )
    def create(self, request: Request) -> Response:
        serializer = InvitationCreateSerializer(
            data=request.data, context=self.get_serializer_context()
        )
        serializer.is_valid(raise_exception=True)
        invitation, raw_token = services.create_invitation(
            actor=self.actor, **serializer.validated_data
        )
        payload = {
            **InvitationSerializer(invitation).data,
            "token": raw_token,
            "accept_url": services.build_accept_url(raw_token),
        }
        return Response(payload, status=status.HTTP_201_CREATED)

    @extend_schema(
        summary="Resend a pending invitation with a new link",
        description=(
            "Issues a new token (the previous link stops working) and queues a new email. "
            "The new token is returned once, like at creation."
        ),
        request=None,
        responses={200: InvitationCreatedSerializer},
    )
    @action(detail=True, methods=["post"])
    def resend(self, request: Request, pk: str | None = None) -> Response:
        invitation, raw_token = services.resend_invitation(
            actor=self.actor, invitation=self.get_object()
        )
        return Response(
            {
                **InvitationSerializer(invitation).data,
                "token": raw_token,
                "accept_url": services.build_accept_url(raw_token),
            }
        )

    @extend_schema(summary="Revoke a pending invitation", request=None)
    @action(detail=True, methods=["post"])
    def revoke(self, request: Request, pk: str | None = None) -> Response:
        invitation = services.revoke_invitation(actor=self.actor, invitation=self.get_object())
        return Response(InvitationSerializer(invitation).data)


class AcceptInvitationView(APIView):
    """Public endpoint: redeem an invitation token and create the account."""

    authentication_classes = ()
    permission_classes = (AllowAny,)
    throttle_classes = (ClientScopedRateThrottle,)
    throttle_scope = "auth"

    @extend_schema(
        tags=["invitations"],
        summary="Accept an invitation",
        request=AcceptInvitationSerializer,
        responses={
            201: UserSerializer,
            400: OpenApiResponse(description="Invalid/expired token or weak password."),
        },
        auth=[],
    )
    def post(self, request: Request) -> Response:
        serializer = AcceptInvitationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = services.accept_invitation(
            raw_token=serializer.validated_data["token"],
            password=serializer.validated_data["password"],
            full_name=serializer.validated_data["full_name"],
        )
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
