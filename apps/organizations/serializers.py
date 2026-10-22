from __future__ import annotations

from rest_framework import serializers

from apps.common.serializers import StrictModelSerializer
from apps.organizations.models import Organization


class OrganizationSerializer(StrictModelSerializer):
    member_count = serializers.IntegerField(read_only=True)
    slug = serializers.SlugField(max_length=63, required=False)

    class Meta:
        model = Organization
        fields = ("id", "name", "slug", "is_active", "member_count", "created_at", "updated_at")
        read_only_fields = ("id", "member_count", "created_at", "updated_at")

    def validate_name(self, value: str) -> str:
        value = value.strip()
        clash = Organization.objects.filter(name__iexact=value)
        if self.instance is not None:
            clash = clash.exclude(pk=self.instance.pk)
        if clash.exists():
            raise serializers.ValidationError("An organization with this name already exists.")
        return value

    def validate_slug(self, value: str) -> str:
        clash = Organization.objects.filter(slug=value)
        if self.instance is not None:
            clash = clash.exclude(pk=self.instance.pk)
        if clash.exists():
            raise serializers.ValidationError("An organization with this slug already exists.")
        return value
