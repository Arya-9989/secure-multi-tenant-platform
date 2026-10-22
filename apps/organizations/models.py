from __future__ import annotations

import uuid
from typing import ClassVar

from django.db import models
from django.db.models.functions import Lower

from apps.common.tenancy import TenantQuerySet


class OrganizationQuerySet(TenantQuerySet["Organization"]):
    # An organization "belongs" to itself: members can see exactly one row.
    tenant_field: ClassVar[str] = "pk"


class Organization(models.Model):
    """A tenant. Every tenant-owned row references one of these."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=150)
    slug = models.SlugField(max_length=63, unique=True)
    is_active = models.BooleanField(
        default=True,
        help_text="Inactive organizations cannot authenticate; data is retained.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = OrganizationQuerySet.as_manager()

    class Meta:
        ordering = ("name",)
        constraints = (models.UniqueConstraint(Lower("name"), name="organization_name_ci_unique"),)

    def __str__(self) -> str:
        return self.name

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.id
