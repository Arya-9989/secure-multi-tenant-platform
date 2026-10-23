"""Hash chains over the audit log (ADR 0006).

Each tenant's events (and the platform's) form a chain: event *n* stores the hash
of event *n-1*, and its own hash is an HMAC over its content and that link. The
HMAC key is not in the database, so rewriting rows means recomputing hashes
nobody without the key can compute; deleting or reordering rows breaks the
links; and verification reports exactly which row.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC
from functools import lru_cache
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder
from django.core.signals import setting_changed
from django.db import connection
from django.dispatch import receiver

GENESIS = "0" * 64
PLATFORM_CHAIN = "platform"

# Every content field, in the order they are hashed. Changing this list is a new
# chain format: existing rows would no longer verify.
HASHED_FIELDS = (
    "id",
    "chain_seq",
    "prev_hash",
    "created_at",
    "organization_id",
    "actor_id",
    "actor_email",
    "action",
    "target_type",
    "target_id",
    "metadata",
    "ip_address",
    "user_agent",
    "request_id",
)


def chain_key(organization_id: uuid.UUID | str | None) -> str:
    return str(organization_id) if organization_id else PLATFORM_CHAIN


@lru_cache(maxsize=1)
def _key() -> bytes:
    configured: str = settings.AUDIT_CHAIN_KEY
    if configured:
        return configured.encode()
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"audit-log", info=b"hash-chain")
    return hkdf.derive(settings.SECRET_KEY.encode())


@receiver(setting_changed)
def _reset_key(*, setting: str, **kwargs: object) -> None:
    if setting in {"AUDIT_CHAIN_KEY", "SECRET_KEY"}:
        _key.cache_clear()


def normalize_metadata(metadata: Mapping[str, Any]) -> Any:
    """What the JSON column will hand back, so write-time and read-time hashes agree."""
    return json.loads(json.dumps(metadata, cls=DjangoJSONEncoder))


def _normalize(name: str, value: Any) -> Any:
    if value is None:
        return None
    if name == "created_at":
        return value.astimezone(UTC).isoformat(timespec="microseconds")
    if name == "ip_address":
        return str(ipaddress.ip_address(value))
    if name == "metadata":
        return normalize_metadata(value)
    if name in {"id", "organization_id", "actor_id"}:
        return str(value)
    return value


def compute_hash(values: Mapping[str, Any]) -> str:
    payload = json.dumps(
        [_normalize(name, values[name]) for name in HASHED_FIELDS],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hmac.new(_key(), payload.encode(), hashlib.sha256).hexdigest()


def lock_chain(organization_id: uuid.UUID | str | None) -> None:
    """Serialise appends to one chain until the surrounding transaction ends."""
    if connection.vendor != "postgresql":
        return  # SQLite serialises every write anyway
    digest = hashlib.sha256(f"audit-chain:{chain_key(organization_id)}".encode()).digest()
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT pg_advisory_xact_lock(%s)", [int.from_bytes(digest[:8], "big", signed=True)]
        )


# ---------------------------------------------------------------- verification
@dataclass(frozen=True, slots=True)
class Finding:
    chain: str
    kind: str  # modified | gap | relinked | duplicate | truncated | bad_start
    detail: str
    row_id: str | None = None

    def __str__(self) -> str:
        where = f" (row {self.row_id})" if self.row_id else ""
        return f"[{self.chain}] {self.kind}: {self.detail}{where}"


@dataclass
class ChainReport:
    chain: str
    rows: int = 0
    head_seq: int = 0
    findings: list[Finding] = field(default_factory=list)


def verify_chain(
    chain: str,
    rows: Iterator[Mapping[str, Any]],
    *,
    start_seq: int = 0,
    start_hash: str = GENESIS,
    exported_seq: int = 0,
) -> ChainReport:
    """Check one chain's rows, given in ``chain_seq`` order, from its starting point."""
    report = ChainReport(chain=chain, head_seq=start_seq)
    expected_seq, expected_prev = start_seq + 1, start_hash
    for row in rows:
        report.rows += 1
        seq, row_id = int(row["chain_seq"]), str(row["id"])
        if seq < expected_seq:
            report.findings.append(
                Finding(chain, "duplicate", f"sequence {seq} appears again", row_id)
            )
            continue
        if seq > expected_seq:
            missing = f"{expected_seq}" if seq == expected_seq + 1 else f"{expected_seq}-{seq - 1}"
            report.findings.append(
                Finding(chain, "gap", f"sequence {missing} missing (deleted rows)", row_id)
            )
        elif row["prev_hash"] != expected_prev:
            report.findings.append(
                Finding(chain, "relinked", f"row {seq} does not follow row {seq - 1}", row_id)
            )
        if not hmac.compare_digest(compute_hash(row), str(row["hash"])):
            report.findings.append(
                Finding(chain, "modified", f"row {seq}'s content does not match its hash", row_id)
            )
        expected_seq, expected_prev = seq + 1, str(row["hash"])
        report.head_seq = seq
    if exported_seq > report.head_seq:
        report.findings.append(
            Finding(
                chain,
                "truncated",
                f"the SIEM already received sequence {exported_seq}, the table ends at "
                f"{report.head_seq}",
            )
        )
    return report


def as_values(entry: Any) -> dict[str, Any]:
    return {name: getattr(entry, name) for name in HASHED_FIELDS}
