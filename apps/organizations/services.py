from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.db import transaction
from django.utils.text import slugify

from apps.accounts.models import SessionEndReason
from apps.accounts.roles import Perm
from apps.accounts.services import revoke_tokens_of
from apps.auditlogs.models import AuditAction
from apps.auditlogs.services import record
from apps.common.guards import require_permission, require_same_tenant
from apps.organizations.models import Organization

if TYPE_CHECKING:
    from apps.accounts.models import User

MAX_SLUG_LENGTH = Organization._meta.get_field("slug").max_length or 63


def unique_slug(name: str) -> str:
    base = slugify(name)[: MAX_SLUG_LENGTH - 4] or "org"
    slug, suffix = base, 2
    while Organization.objects.filter(slug=slug).exists():
        slug, suffix = f"{base}-{suffix}", suffix + 1
    return slug


def create_organization(
    *, actor: User, name: str, slug: str | None = None, is_active: bool = True
) -> Organization:
    require_permission(actor, Perm.ORGANIZATION_MANAGE)
    with transaction.atomic():
        organization = Organization.objects.create(
            name=name, slug=slug or unique_slug(name), is_active=is_active
        )
        record(
            AuditAction.ORGANIZATION_CREATED,
            actor=actor,
            organization=organization,
            target=organization,
            metadata={"name": organization.name, "slug": organization.slug},
        )
    return organization


def update_organization(
    *, actor: User, organization: Organization, changes: dict[str, Any]
) -> Organization:
    require_permission(actor, Perm.ORGANIZATION_MANAGE)
    require_same_tenant(actor, organization)
    diff = {
        field: {"from": getattr(organization, field), "to": value}
        for field, value in changes.items()
        if getattr(organization, field) != value
    }
    if not diff:
        return organization
    with transaction.atomic():
        for field, change in diff.items():
            setattr(organization, field, change["to"])
        organization.save(update_fields=[*diff, "updated_at"])
        if diff.get("is_active", {}).get("to") is False:
            # Members are cut off on their next request anyway (authentication
            # checks the organization). Revoking their tokens as well means a
            # later reactivation does not bring old sessions back to life.
            revoke_tokens_of(organization.users.all(), SessionEndReason.ORGANIZATION_DEACTIVATED)
        record(
            AuditAction.ORGANIZATION_UPDATED,
            actor=actor,
            organization=organization,
            target=organization,
            metadata={"changes": diff},
        )
    return organization
