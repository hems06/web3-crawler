"""User notifications. Stored in the database and optionally posted to a
webhook the user configured. Notifications never trigger any action."""

from __future__ import annotations

import logging

import httpx
from sqlalchemy.orm import Session

from .config import get_settings
from .models import Notification

log = logging.getLogger("crawler.notify")

PRIVATE_PROGRAM_DISCOVERED = "private_program_discovered"
AUTHORIZATION_EMAIL_READY = "authorization_email_ready"
RESPONSE_RECEIVED = "response_received"
AUTHORIZATION_CONFIRMED = "authorization_confirmed"
SCOPE_CHANGED = "scope_changed"
BOUNTY_CONFIRMED = "bounty_confirmed"
AUTHORIZATION_EXPIRED = "authorization_expired"


def notify(session: Session, kind: str, message: str, program_id: int | None = None) -> Notification:
    note = Notification(kind=kind, message=message, program_id=program_id)
    session.add(note)
    session.flush()
    log.warning("NOTIFY [%s] %s", kind, message)
    url = get_settings().notify_webhook_url
    if url:
        try:
            httpx.post(
                url,
                json={"kind": kind, "message": message, "program_id": program_id},
                timeout=10,
            )
        except httpx.HTTPError as exc:  # notification failure must not break the pipeline
            log.error("webhook notification failed: %s", exc)
    return note
