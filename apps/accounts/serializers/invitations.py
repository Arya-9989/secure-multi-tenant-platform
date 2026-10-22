from __future__ import annotations

from typing import Any

from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied

from apps.accounts.models import Invitation
from apps.accounts.roles import ASSIGNABLE_ROLE_CHOICES
from apps.common.serializers import StrictSerializer
from apps.common.tenancy import TenantScopedPrimaryKeyRelatedField, resolve_user
from apps.organizations.models import Organization


class InvitationSerializer(serializers.ModelSerializer[Invitation]):
    status = serializers.CharField(read_only=True)
    invited_by = serializers.EmailField(source="invited_by.email", read_only=True)

    class Meta:
        model = Invitation
        fields: tuple[str, ...] = (
            "id",
            "organization",
            "email",
            "role",
            "status",
            "invited_by",
            "created_at",
            "expires_at",
            "accepted_at",
            "revoked_at",
            "email_status",
            "email_attempts",
            "email_sent_at",
            "email_last_error",
        )
        read_only_fields: tuple[str, ...] = fields


class InvitationCreatedSerializer(InvitationSerializer):
    token = serializers.CharField(
        read_only=True, help_text="Shown once. Only its SHA-256 digest is stored."
    )
    accept_url = serializers.CharField(read_only=True)

    class Meta(InvitationSerializer.Meta):
        fields = (*InvitationSerializer.Meta.fields, "token", "accept_url")
        read_only_fields = fields


class InvitationCreateSerializer(StrictSerializer):
    email = serializers.EmailField(max_length=254)
    role = serializers.ChoiceField(choices=ASSIGNABLE_ROLE_CHOICES)
    organization = TenantScopedPrimaryKeyRelatedField(
        queryset=Organization.objects.all(),
        required=False,
        help_text="Super admins only. Defaults to the caller's own organization.",
    )

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        user = resolve_user(self.context["request"].user)
        if user is None:  # unreachable behind the view's permission classes
            raise PermissionDenied
        if "organization" not in attrs:
            if user.organization is None:
                raise serializers.ValidationError({"organization": ["This field is required."]})
            attrs["organization"] = user.organization
        return attrs


class AcceptInvitationSerializer(StrictSerializer):
    token = serializers.CharField(max_length=128)
    password = serializers.CharField(style={"input_type": "password"}, trim_whitespace=False)
    full_name = serializers.CharField(max_length=150, required=False, default="")
