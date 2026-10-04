"""Settings saved by the first-run setup (`crawler setup`).

Stored outside the repository in ``~/.config/web3-crawler/config.json``
(directory 0700, file 0600; override with CRAWLER_USER_CONFIG). The OpenAI
API key goes to the OS keyring when one is available, otherwise into the
same private file. Environment variables win over these saved values;
saved values win over the .env file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from pydantic.fields import FieldInfo
from pydantic_settings import PydanticBaseSettingsSource

KEYRING_SERVICE = "web3-crawler"
SECRET_KEYS = ("openai_api_key",)
SAVED_KEYS = ("researcher_name", "researcher_contact", "openai_api_key", "openai_model", "openai_base_url")


def path() -> Path:
    return Path(os.environ.get("CRAWLER_USER_CONFIG") or Path.home() / ".config" / "web3-crawler" / "config.json").expanduser()


def _keyring():
    try:
        import keyring
        from keyring.backends import fail

        return None if isinstance(keyring.get_keyring(), fail.Keyring) else keyring
    except Exception:  # noqa: BLE001
        return None


def load() -> dict:
    p = path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
    except (OSError, ValueError):
        return {}
    for key in SECRET_KEYS:
        if data.pop(f"{key}_in_keyring", False):
            kr = _keyring()
            data[key] = (kr.get_password(KEYRING_SERVICE, key) if kr else "") or ""
    return data


def save(values: dict, use_keyring: bool = True) -> Path:
    """Merge values into the saved config."""
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(p.parent, 0o700)
    current = json.loads(p.read_text()) if p.exists() else {}
    kr = _keyring() if use_keyring else None
    for key, value in values.items():
        if key in SECRET_KEYS and value and kr:
            kr.set_password(KEYRING_SERVICE, key, value)
            current[key] = ""
            current[f"{key}_in_keyring"] = True
        else:
            current[key] = value
            if key in SECRET_KEYS:
                current.pop(f"{key}_in_keyring", None)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(current, fh, indent=2)
    os.chmod(p, 0o600)
    return p


def setup_done() -> bool:
    return bool(load().get("setup_completed"))


class SavedConfigSource(PydanticBaseSettingsSource):
    """pydantic-settings source for the saved config (lowest priority)."""

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        data = load()
        return {k: v for k, v in data.items() if k in SAVED_KEYS and v not in (None, "")}


def forget_secret(key: str) -> None:
    kr = _keyring()
    if kr:
        try:
            kr.delete_password(KEYRING_SERVICE, key)
        except Exception:  # noqa: BLE001 - nothing stored
            pass
    p = path()
    if p.exists():
        current = json.loads(p.read_text())
        current.pop(f"{key}_in_keyring", None)
        current[key] = ""
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(current, fh, indent=2)
