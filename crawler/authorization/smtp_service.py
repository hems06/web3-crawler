"""SMTP sending service with one-time setup.

The first send asks for SMTP settings and saves them, so later sends do not
ask again. Settings live outside the repository and the database:

* host, port, security, username and from address go to
  ``~/.config/web3-crawler/smtp.json`` (directory 0700, file 0600);
* the password goes to the OS keyring when the optional ``keyring`` package
  and a backend are available, otherwise into the same 0600 file.

SMTP_* environment variables override the saved file. Plain-text SMTP is
not supported: the connection uses STARTTLS or implicit TLS.

Setup also asks once whether emails may be sent without a per-email
confirmation (``auto_send``). That standing approval is saved with the
settings and can be withdrawn with ``crawler email setup`` or ``forget``.
"""

from __future__ import annotations

import json
import os
import smtplib
import ssl
from dataclasses import asdict, dataclass
from email.message import EmailMessage
from pathlib import Path

from ..config import Settings, get_settings

KEYRING_SERVICE = "web3-crawler-smtp"
SECURITY_MODES = ("starttls", "ssl")


class EmailNotConfigured(RuntimeError):
    pass


@dataclass
class SmtpConfig:
    host: str
    port: int = 587
    security: str = "starttls"
    username: str = ""
    from_addr: str = ""
    password: str = ""
    # Standing approval, given once at setup: send authorization emails
    # without a per-email confirmation (subject to the guards in
    # manager.auto_send_blockers).
    auto_send: bool = False

    def public(self) -> dict:
        data = asdict(self)
        data["password"] = "set" if self.password else "not set"
        return data


def _keyring():
    try:
        import keyring  # optional dependency
        from keyring.backends import fail

        if isinstance(keyring.get_keyring(), fail.Keyring):
            return None
        return keyring
    except Exception:  # noqa: BLE001 - any keyring problem means "use the file"
        return None


def config_path(settings: Settings | None = None) -> Path:
    return Path((settings or get_settings()).smtp_config_file).expanduser()


def load(settings: Settings | None = None) -> SmtpConfig | None:
    """Environment first, then the saved file. None when nothing is set up."""
    settings = settings or get_settings()
    if settings.smtp_host:
        return SmtpConfig(
            host=settings.smtp_host,
            port=settings.smtp_port,
            security=settings.smtp_security,
            username=settings.smtp_username,
            from_addr=settings.smtp_from or settings.smtp_username,
            password=settings.smtp_password,
            auto_send=settings.auto_send,
        )
    path = config_path(settings)
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    password = data.pop("password", "") or ""
    if data.pop("password_in_keyring", False):
        kr = _keyring()
        password = (kr.get_password(KEYRING_SERVICE, data.get("username") or data["host"]) if kr else "") or ""
    return SmtpConfig(password=password, **{k: v for k, v in data.items() if k in SmtpConfig.__dataclass_fields__})


def save(cfg: SmtpConfig, settings: Settings | None = None, use_keyring: bool = True) -> Path:
    if cfg.security not in SECURITY_MODES:
        raise ValueError(f"security must be one of {SECURITY_MODES}")
    path = config_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    data = asdict(cfg)
    kr = _keyring() if use_keyring else None
    if kr and cfg.password:
        kr.set_password(KEYRING_SERVICE, cfg.username or cfg.host, cfg.password)
        data["password"] = ""
        data["password_in_keyring"] = True
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=2)
    os.chmod(path, 0o600)
    return path


def forget(settings: Settings | None = None) -> bool:
    path = config_path(settings)
    if not path.exists():
        return False
    data = json.loads(path.read_text())
    kr = _keyring()
    if kr and data.get("password_in_keyring"):
        try:
            kr.delete_password(KEYRING_SERVICE, data.get("username") or data["host"])
        except Exception:  # noqa: BLE001
            pass
    path.unlink()
    return True


def effective_provider(settings: Settings | None = None) -> str:
    """'smtp' when sending is possible, otherwise 'none'."""
    settings = settings or get_settings()
    if settings.email_provider == "none":
        return "none"
    if settings.email_provider == "smtp":
        return "smtp"
    return "smtp" if load(settings) else "none"


def _connect(cfg: SmtpConfig) -> smtplib.SMTP:
    context = ssl.create_default_context()
    if cfg.security == "ssl":
        smtp = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=30, context=context)
    else:
        smtp = smtplib.SMTP(cfg.host, cfg.port, timeout=30)
        smtp.starttls(context=context)
    if cfg.username:
        smtp.login(cfg.username, cfg.password)
    return smtp


def test_connection(cfg: SmtpConfig) -> None:
    """Connect and log in without sending anything."""
    with _connect(cfg):
        pass


def send(to: str, subject: str, body: str, settings: Settings | None = None, cfg: SmtpConfig | None = None) -> None:
    settings = settings or get_settings()
    if effective_provider(settings) != "smtp":
        raise EmailNotConfigured("email sending is disabled (EMAIL_PROVIDER=none or no SMTP settings saved)")
    cfg = cfg or load(settings)
    if cfg is None:
        raise EmailNotConfigured("no SMTP settings; run `crawler email setup`")
    msg = EmailMessage()
    msg["From"] = cfg.from_addr or cfg.username
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with _connect(cfg) as smtp:
        smtp.send_message(msg)
