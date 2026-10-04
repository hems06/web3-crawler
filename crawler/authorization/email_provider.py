"""Optional, user-controlled email integration.

Sending goes through smtp_service, which asks for SMTP settings once and
saves them. Each email is still sent only after the user approved that
specific request. EMAIL_PROVIDER=none disables sending entirely.
"""

from __future__ import annotations

import email
import imaplib
from dataclasses import dataclass
from email.utils import parseaddr

from ..config import Settings, get_settings
from . import smtp_service
from .smtp_service import EmailNotConfigured  # noqa: F401 - re-exported


@dataclass
class InboundEmail:
    sender: str
    subject: str
    body: str
    message_id: str | None


def send_email(to: str, subject: str, body: str, settings: Settings | None = None) -> None:
    smtp_service.send(to, subject, body, settings)


def _plain_body(msg: email.message.Message) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not part.get_filename():
                return part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", "replace")
        return ""
    payload = msg.get_payload(decode=True) or b""
    return payload.decode(msg.get_content_charset() or "utf-8", "replace")


def fetch_unseen(settings: Settings | None = None) -> list[InboundEmail]:
    """Read unseen messages from the configured mailbox (read-only access)."""
    settings = settings or get_settings()
    if not settings.imap_host:
        raise EmailNotConfigured("IMAP_HOST is empty")
    out: list[InboundEmail] = []
    with imaplib.IMAP4_SSL(settings.imap_host) as imap:
        imap.login(settings.imap_username, settings.imap_password)
        imap.select(settings.imap_folder, readonly=True)
        _, data = imap.search(None, "UNSEEN")
        for num in (data[0] or b"").split():
            _, msg_data = imap.fetch(num, "(BODY.PEEK[])")
            msg = email.message_from_bytes(msg_data[0][1])
            out.append(
                InboundEmail(
                    sender=parseaddr(msg.get("From", ""))[1],
                    subject=msg.get("Subject", ""),
                    body=_plain_body(msg),
                    message_id=msg.get("Message-ID"),
                )
            )
    return out
