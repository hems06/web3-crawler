"""Optional, user-controlled email integration.

EMAIL_PROVIDER=none (default): nothing is ever sent; the user copies the
draft into their own mail client and marks it sent.
EMAIL_PROVIDER=smtp: an email is sent only after the user approved that
specific request (manager.approve_request) and then asked to send it.
"""

from __future__ import annotations

import email
import imaplib
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import parseaddr

from ..config import Settings, get_settings


class EmailNotConfigured(RuntimeError):
    pass


@dataclass
class InboundEmail:
    sender: str
    subject: str
    body: str
    message_id: str | None


def send_email(to: str, subject: str, body: str, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    if settings.email_provider != "smtp" or not settings.smtp_host:
        raise EmailNotConfigured("EMAIL_PROVIDER is not smtp or SMTP_HOST is empty")
    msg = EmailMessage()
    msg["From"] = settings.smtp_from or settings.smtp_username
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(msg)


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
