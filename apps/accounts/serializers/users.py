from __future__ import annotations

from rest_framework import serializers

from apps.accounts.models import User
from apps.accounts.roles import ASSIGNABLE_ROLE_CHOICES
from apps.common.serializers import StrictModelSerializer


class UserSerializer(serializers.ModelSerializer[User]):
    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "full_name",
            "role",
            "organization",
            "is_active",
            "deactivated_at",
            "date_joined",
            "last_login",
        )
        read_only_fields = fields


class MeSerializer(StrictModelSerializer):
    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "full_name",
            "role",
            "organization",
            "is_active",
            "date_joined",
            "last_login",
        )
        read_only_fields = tuple(f for f in fields if f != "full_name")


class UserRoleUpdateSerializer(StrictModelSerializer):
    """The only user attribute an admin may change. Organization is immutable."""

    role = serializers.ChoiceField(choices=ASSIGNABLE_ROLE_CHOICES)

    class Meta:
        model = User
        fields = ("role",)
