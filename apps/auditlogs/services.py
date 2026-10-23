from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any

from django.db import transaction
from django.db.models import Model
from django.utils import timezone

from apps.auditlogs import chain
from apps.auditlogs.models import AuditAction, AuditChainCheckpoint, AuditLog
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
    together. The event is appended to its tenant's hash chain (ADR 0006).
    """
    context = get_request_context()
    organization_id = organization.pk if organization is not None else None
    with transaction.atomic():
        chain.lock_chain(organization_id)
        seq, prev_hash, not_before = _chain_head(organization_id)
        entry = AuditLog(
            # Never before the chain's head, so sequence and time order agree.
            created_at=max(timezone.now(), not_before) if not_before else timezone.now(),
            action=action,
            actor=actor,
            actor_email=actor.email if actor else "",
            organization=organization,
            target_type=target._meta.label_lower if target is not None else "",
            target_id=str(target.pk) if target is not None else "",
            metadata=chain.normalize_metadata(metadata or {}),
            ip_address=context.ip_address if context else None,
            user_agent=context.user_agent if context else "",
            request_id=context.request_id if context else "",
            chain_seq=seq + 1,
            prev_hash=prev_hash,
        )
        entry.hash = chain.compute_hash(chain.as_values(entry))
        entry.save()
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


def _chain_head(organization_id: Any) -> tuple[int, str, datetime | None]:
    """The chain's last sequence number, hash and time (or its retention checkpoint)."""
    head = (
        AuditLog.objects.filter(organization_id=organization_id)
        .order_by("-chain_seq")
        .values_list("chain_seq", "hash", "created_at")
        .first()
    )
    if head is not None:
        return head
    checkpoint = (
        AuditChainCheckpoint.objects.filter(organization_id=organization_id)
        .order_by("-chain_seq")
        .values_list("chain_seq", "hash", "last_created_at")
        .first()
    )
    return checkpoint if checkpoint is not None else (0, chain.GENESIS, None)
