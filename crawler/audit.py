"""Append-only, hash-chained audit log."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditEvent, as_utc, utcnow

log = logging.getLogger("crawler.audit")

GENESIS = "0" * 64


def _digest(prev_hash: str, created_at: str, event_type: str, program_id, payload: dict) -> str:
    body = json.dumps(
        [prev_hash, created_at, event_type, program_id, payload],
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )
    return hashlib.sha256(body.encode()).hexdigest()


def record(
    session: Session, event_type: str, program_id: int | None = None, **payload: Any
) -> AuditEvent:
    """Append an audit event. Rows are never updated or deleted."""
    last = session.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)).first()
    prev_hash = last.hash if last else GENESIS
    created = utcnow()
    payload = json.loads(json.dumps(payload, default=str))
    event = AuditEvent(
        created_at=created,
        event_type=str(event_type),
        program_id=program_id,
        payload=payload,
        prev_hash=prev_hash,
        hash=_digest(prev_hash, created.isoformat(), str(event_type), program_id, payload),
    )
    session.add(event)
    session.flush()
    log.info("audit %s program=%s %s", event_type, program_id, payload)
    return event


def verify_chain(session: Session) -> tuple[bool, int | None]:
    """Return (ok, first_bad_event_id)."""
    prev = GENESIS
    for event in session.scalars(select(AuditEvent).order_by(AuditEvent.id)):
        expected = _digest(
            prev,
            as_utc(event.created_at).isoformat(),
            event.event_type,
            event.program_id,
            event.payload,
        )
        if event.prev_hash != prev or event.hash != expected:
            return False, event.id
        prev = event.hash
    return True, None
