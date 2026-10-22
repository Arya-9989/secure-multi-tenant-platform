from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django.db.models import Model

from apps.auditlogs.models import AuditAction, AuditLog
from apps.common.context import get_request_context

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.organizations.models import Organization

logger = logging.getLogger("apps.audit")


def record(
    action: AuditAction,
    *,
    actor: User | None = None,
    organization: Organization | None = None,
    target: Model | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    """Append an audit event, enriched with the current request's context.

    Call this inside the same ``transaction.atomic()`` block as the change it
    describes, so the change and its audit record commit (or roll back)
    together.
    """
    context = get_request_context()
    entry = AuditLog.objects.create(
        action=action,
        actor=actor,
        actor_email=actor.email if actor else "",
        organization=organization,
        target_type=target._meta.label_lower if target is not None else "",
        target_id=str(target.pk) if target is not None else "",
        metadata=metadata or {},
        ip_address=context.ip_address if context else None,
        user_agent=context.user_agent if context else "",
        request_id=context.request_id if context else "",
    )
    logger.info(
        "audit %s",
        action.value,
        extra={
            "audit_action": action.value,
            "actor_id": str(actor.pk) if actor else None,
            "organization_id": str(organization.pk) if organization else None,
            "target": f"{entry.target_type}:{entry.target_id}" if target is not None else None,
        },
    )
    return entry
