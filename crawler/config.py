"""Settings from the environment plus YAML files under config/."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parent.parent


def _split(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [v.strip() for v in str(value).split(",") if v.strip()]


class Settings(BaseSettings):
    # The install's own .env first, then one in the current directory.
    model_config = SettingsConfigDict(env_file=(REPO_ROOT / ".env", ".env"), extra="ignore")

    database_url: str = "sqlite:///./data/crawler.db"
    redis_url: str = "redis://localhost:6379/0"
    config_dir: Path = REPO_ROOT / "config"

    platform_exclusions: str = ""
    program_type_filter: str = ""
    min_bounty: float = 0
    private_only: bool = True

    require_bounty_confirmation: bool = True
    require_explicit_scope: bool = True
    authorization_expiry: int = 90  # days
    research_mode: bool = False

    # "" (unset): send through saved SMTP settings if any, else drafts only.
    # "none": never send. "smtp": send (settings from env or the saved file).
    email_provider: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"  # starttls or ssl
    # Cap on emails sent under the standing approval (auto_send).
    auto_send_max_per_hour: int = 10
    # Standing approval when SMTP comes from SMTP_* env vars instead of the
    # saved file (the saved file stores its own answer).
    auto_send: bool = False
    smtp_config_file: Path = Path.home() / ".config" / "web3-crawler" / "smtp.json"
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    imap_host: str = ""
    imap_username: str = ""
    imap_password: str = ""
    imap_folder: str = "INBOX"

    researcher_name: str = "Your Name"
    researcher_contact: str = "you@example.com"

    hackerone_api_username: str = ""
    hackerone_api_token: str = ""
    crawler_user_agent: str = "web3-crawler/0.1 (+authorization-first research tool)"
    request_delay_seconds: float = 2.0

    etherscan_api_key: str = ""
    notify_webhook_url: str = ""

    @field_validator("email_provider")
    @classmethod
    def _provider(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in {"", "none", "smtp"}:
            raise ValueError("EMAIL_PROVIDER must be empty, 'none' or 'smtp'")
        return v

    @property
    def platform_exclusion_list(self) -> list[str]:
        return [p.lower() for p in _split(self.platform_exclusions)]

    @property
    def program_type_filter_list(self) -> list[str]:
        return [p.upper() for p in _split(self.program_type_filter)]

    def load_yaml(self, name: str) -> dict:
        path = Path(self.config_dir) / name
        if not path.exists():
            return {}
        with path.open() as fh:
            return yaml.safe_load(fh) or {}


@lru_cache
def get_settings() -> Settings:
    return Settings()


class PlatformConfig:
    """Parsed config/platforms.yaml merged with PLATFORM_EXCLUSIONS."""

    ACCESS_KEYS = (
        "platform_reputation_required",
        "invite_required",
        "application_required",
        "private_program_supported",
    )

    def __init__(self, data: dict, extra_exclusions: list[str] | None = None):
        self.platforms: dict[str, dict] = {
            k.lower(): v or {} for k, v in (data.get("platforms") or {}).items()
        }
        self.excluded_platforms = {p.lower() for p in data.get("excluded_platforms") or []}
        self.excluded_platforms.update(p.lower() for p in extra_exclusions or [])
        self.excluded_program_types = {
            t.lower() for t in data.get("excluded_program_types") or []
        }
        self.type_definitions: dict[str, dict] = {
            k.lower(): v or {} for k, v in (data.get("program_type_definitions") or {}).items()
        }
        unknown = self.excluded_program_types - set(self.type_definitions)
        if unknown:
            raise ValueError(
                f"excluded_program_types references undefined types: {sorted(unknown)}"
            )

    @classmethod
    def load(cls, settings: Settings | None = None) -> "PlatformConfig":
        settings = settings or get_settings()
        return cls(settings.load_yaml("platforms.yaml"), settings.platform_exclusion_list)

    def defaults_for(self, slug: str) -> dict:
        info = self.platforms.get(slug.lower()) or self.platforms.get("unknown") or {}
        return {k: bool(info.get(k, False)) for k in self.ACCESS_KEYS}

    def program_type_tags(self, props: dict) -> set[str]:
        """Names of every program type definition the given properties match."""
        tags = set()
        for name, definition in self.type_definitions.items():
            if definition and all(bool(props.get(k)) == bool(v) for k, v in definition.items()):
                tags.add(name)
        return tags
