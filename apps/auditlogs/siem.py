"""Streaming the audit log to a SIEM over HTTP (ADR 0006).

Events go out as newline-delimited JSON, signed with HMAC-SHA256, one batch per
chain at a time and in sequence order. A per-chain cursor records the last
sequence number the SIEM acknowledged (any 2xx), so delivery is at-least-once,
ordered, and resumes where it stopped. Every event carries its ``id`` and
``hash``, which a receiver can use to deduplicate and to cross-check the chain.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import random
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.db import transaction

from apps.auditlogs import chain
from apps.auditlogs.models import AuditExportCursor, AuditLog
from apps.common import rls
from apps.organizations.models import Organization

logger = logging.getLogger(__name__)

SIGNATURE_HEADER = "X-Audit-Signature"


class SiemDeliveryError(Exception):
    pass


def as_event(entry: AuditLog) -> dict[str, Any]:
    return {
        "id": str(entry.pk),
        "chain": chain.chain_key(entry.organization_id),
        "seq": entry.chain_seq,
        "prev_hash": entry.prev_hash,
        "hash": entry.hash,
        "created_at": entry.created_at.isoformat(),
        "action": entry.action,
        "organization_id": str(entry.organization_id) if entry.organization_id else None,
        "actor_id": str(entry.actor_id) if entry.actor_id else None,
        "actor_email": entry.actor_email,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "metadata": entry.metadata,
        "ip_address": entry.ip_address,
        "user_agent": entry.user_agent,
        "request_id": entry.request_id,
    }


def sign(body: bytes) -> str:
    secret: str = settings.AUDIT_SIEM_SECRET
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def post(body: bytes, *, batch: str, sleep: Callable[[float], object] | None = None) -> None:
    """Deliver one batch, retrying with exponential backoff and jitter."""
    pause = sleep or time.sleep
    attempts: int = settings.AUDIT_SIEM_MAX_ATTEMPTS
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(  # noqa: S310 - the operator's configured URL
            settings.AUDIT_SIEM_URL,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/x-ndjson",
                SIGNATURE_HEADER: sign(body),
                "X-Audit-Batch": batch,
            },
        )
        try:
            with urllib.request.urlopen(  # noqa: S310
                request, timeout=settings.AUDIT_SIEM_TIMEOUT_SECONDS
            ) as response:
                if 200 <= response.status < 300:
                    return
                reason = f"HTTP {response.status}"
        except urllib.error.HTTPError as exc:
            reason = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = str(exc)
        logger.warning("SIEM delivery failed (%s), attempt %s of %s", reason, attempt, attempts)
        if attempt < attempts:
            pause(min(30.0, 0.5 * 2 ** (attempt - 1)) * (0.5 + random.random()))  # noqa: S311
    msg = f"The SIEM did not accept batch {batch}"
    raise SiemDeliveryError(msg)


@dataclass(frozen=True, slots=True)
class ShipResult:
    events: int
    batches: int


def _chains() -> Iterable[str | None]:
    yield None  # the platform chain
    yield from (str(pk) for pk in Organization.objects.order_by("pk").values_list("pk", flat=True))


def ship_once(*, sleep: Callable[[float], object] | None = None) -> ShipResult:
    """Send everything not yet acknowledged, chain by chain, batch by batch."""
    if not settings.AUDIT_SIEM_URL:
        msg = "AUDIT_SIEM_URL is not set."
        raise SiemDeliveryError(msg)
    size: int = settings.AUDIT_SIEM_BATCH_SIZE
    events = batches = 0
    with rls.platform_scope():  # a system job over every tenant's chain
        for organization_id in _chains():
            key = chain.chain_key(organization_id)
            cursor, _ = AuditExportCursor.objects.get_or_create(chain=key)
            tenant: dict[str, Any] = (
                {"organization_id": organization_id} if organization_id else {"organization": None}
            )
            while True:
                batch = list(
                    AuditLog.objects.filter(**tenant, chain_seq__gt=cursor.last_seq).order_by(
                        "chain_seq"
                    )[:size]
                )
                if not batch:
                    break
                body = "".join(json.dumps(as_event(e), sort_keys=True) + "\n" for e in batch)
                label = f"{key}:{batch[0].chain_seq}-{batch[-1].chain_seq}"
                post(body.encode(), batch=label, sleep=sleep)
                with transaction.atomic():
                    cursor.last_seq = batch[-1].chain_seq
                    cursor.save(update_fields=["last_seq", "updated_at"])
                events, batches = events + len(batch), batches + 1
    return ShipResult(events, batches)
