"""
Cryptographic Tamper-Evident Audit Chain Service (BLAKE2b).
Implements a tamper-evident hash chain linking all case lifecycle mutations.
Guarantees non-repudiation and immediate detection of database modifications.
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any
import uuid
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from models import AuditEventType, CaseAuditLog

GENESIS_HASH = "0" * 64


def compute_blake2b(data: str | bytes | dict[str, Any]) -> str:
    """
    Computes a 256-bit BLAKE2b digest for string, bytes, or JSON-serializable dictionary.
    """
    if isinstance(data, dict):
        raw_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
    elif isinstance(data, str):
        raw_bytes = data.encode("utf-8")
    else:
        raw_bytes = data
    return hashlib.blake2b(raw_bytes).hexdigest()


def format_canonical_timestamp(dt: datetime) -> str:
    """
    Returns consistent ISO-8601 string with UTC timezone offset.
    Guarantees deterministic verification regardless of database driver's timezone handling.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()


def compute_event_current_hash(
    prev_hash: str,
    event_type: str,
    payload_hash: str,
    created_at_iso: str,
) -> str:
    """
    Computes BLAKE2b(prev_event_hash + event_type + payload_hash + created_at).
    """
    chain_payload = f"{prev_hash}:{event_type}:{payload_hash}:{created_at_iso}".encode("utf-8")
    return hashlib.blake2b(chain_payload).hexdigest()


def record_audit_event(
    db: Session,
    case_id: str,
    event_type: str | AuditEventType,
    payload_data: str | bytes | dict[str, Any],
) -> CaseAuditLog:
    """
    Appends a new event to the case's cryptographic audit hash chain.
    """
    event_type_str = event_type.value if hasattr(event_type, "value") else str(event_type)
    payload_hash = compute_blake2b(payload_data)

    # 1. Fetch latest audit log for this case to link previous hash
    stmt = (
        select(CaseAuditLog)
        .where(CaseAuditLog.case_id == case_id)
        .order_by(desc(CaseAuditLog.created_at))
    )
    latest_log = db.execute(stmt).scalars().first()
    prev_hash = latest_log.current_hash if latest_log else GENESIS_HASH

    now = datetime.now(timezone.utc)
    now_str = format_canonical_timestamp(now)
    current_hash = compute_event_current_hash(
        prev_hash,
        event_type_str,
        payload_hash,
        now_str,
    )

    entry = CaseAuditLog(
        id=str(uuid.uuid4()),
        case_id=case_id,
        event_type=event_type_str,
        payload_hash=payload_hash,
        prev_event_hash=prev_hash,
        current_hash=current_hash,
        created_at=now,
    )
    db.add(entry)
    db.flush()
    return entry


def verify_case_audit_chain(db: Session, case_id: str) -> dict[str, Any]:
    """
    Verifies the complete audit hash chain for a case from Genesis to the latest record.
    Returns validation status, total events count, and any broken event ID.
    """
    stmt = (
        select(CaseAuditLog)
        .where(CaseAuditLog.case_id == case_id)
        .order_by(CaseAuditLog.created_at.asc())
    )
    records = db.execute(stmt).scalars().all()

    if not records:
        return {
            "is_valid": True,
            "events_count": 0,
            "broken_at": None,
            "latest_hash": None,
            "chain": [],
        }

    expected_prev = GENESIS_HASH
    chain_summary = []

    for entry in records:
        entry_summary = {
            "id": entry.id,
            "eventType": entry.event_type,
            "payloadHash": entry.payload_hash,
            "prevEventHash": entry.prev_event_hash,
            "currentHash": entry.current_hash,
            "createdAt": format_canonical_timestamp(entry.created_at),
        }
        chain_summary.append(entry_summary)

        # Check 1: Chain pointer continuity
        if entry.prev_event_hash != expected_prev:
            return {
                "is_valid": False,
                "events_count": len(records),
                "broken_at": entry.id,
                "reason": f"Broken chain pointer at {entry.id}",
                "latest_hash": entry.current_hash,
                "chain": chain_summary,
            }

        # Check 2: Digest recalculation
        recomputed = compute_event_current_hash(
            entry.prev_event_hash,
            entry.event_type,
            entry.payload_hash,
            format_canonical_timestamp(entry.created_at),
        )
        if entry.current_hash != recomputed:
            return {
                "is_valid": False,
                "events_count": len(records),
                "broken_at": entry.id,
                "reason": f"Tampered digest detected at {entry.id}",
                "latest_hash": entry.current_hash,
                "chain": chain_summary,
            }

        expected_prev = entry.current_hash

    return {
        "is_valid": True,
        "events_count": len(records),
        "broken_at": None,
        "latest_hash": expected_prev,
        "chain": chain_summary,
    }
