"""Turn raw collector output into one common program shape."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any

from .enums import ProgramType
from .scope.engine import guess_asset_type, normalize_chain, normalize_domain, normalize_repo

MONEY_RE = re.compile(
    r"(?P<cur1>\$|USD\s*|US\$)?\s*(?P<num>\d[\d,]*(?:\.\d+)?)\s*(?P<mult>[kKmM](?![a-zA-Z]))?\s*(?P<cur2>USDC|USDT|DAI|USD|ETH|WETH|BTC|ARB|OP)?",
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

_TYPE_ALIASES = {
    "public": ProgramType.PUBLIC,
    "private": ProgramType.PRIVATE,
    "invite": ProgramType.INVITE_ONLY,
    "invite_only": ProgramType.INVITE_ONLY,
    "invite-only": ProgramType.INVITE_ONLY,
    "invitation": ProgramType.INVITE_ONLY,
    "vdp": ProgramType.VDP,
    "disclosure": ProgramType.VDP,
}


def parse_money(value: Any) -> tuple[float | None, str | None]:
    """Parse '$50,000', '100k USDC', 'Up to $1M' into (amount, currency)."""
    if value is None or value == "":
        return None, None
    if isinstance(value, (int, float)):
        return float(value), "USD"
    best: tuple[float | None, str | None] = (None, None)
    for m in MONEY_RE.finditer(str(value)):
        if not (m.group("cur1") or m.group("cur2") or m.group("mult")):
            continue
        amount = float(m.group("num").replace(",", ""))
        mult = (m.group("mult") or "").lower()
        amount *= {"k": 1_000, "m": 1_000_000}.get(mult, 1)
        currency = (m.group("cur2") or "USD").upper()
        if best[0] is None or amount > best[0]:
            best = (amount, currency)
    return best


def parse_date(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def normalize_program_type(value: Any) -> ProgramType:
    if not value:
        return ProgramType.UNKNOWN
    key = str(value).strip().lower().replace(" ", "_")
    if key in _TYPE_ALIASES:
        return _TYPE_ALIASES[key]
    for alias, ptype in _TYPE_ALIASES.items():
        if alias in key:
            return ptype
    return ProgramType.UNKNOWN


def normalize_scope_item(item: Any) -> dict | None:
    if isinstance(item, str):
        item = {"value": item}
    if not isinstance(item, dict) or not item.get("value"):
        return None
    value = str(item["value"]).strip()
    kind = item.get("type") or guess_asset_type(value)
    kind = str(kind).lower()
    if kind == "domain":
        value = value.lower() if value.startswith("*.") else normalize_domain(value)
    elif kind == "repository":
        value = normalize_repo(value) or value
    elif kind == "contract":
        value = value.lower()
    out = {"type": kind, "value": value}
    if item.get("chain"):
        out["chain"] = normalize_chain(item["chain"])
    for extra in ("eligible_for_bounty", "max_severity", "description"):
        if extra in item:
            out[extra] = item[extra]
    return out


@dataclass
class NormalizedProgram:
    name: str
    platform: str
    dedupe_key: str
    collector: str
    project_name: str | None = None
    protocol_name: str | None = None
    program_url: str | None = None
    source_url: str | None = None
    program_type: ProgramType = ProgramType.UNKNOWN
    listed_scope: list[dict] = field(default_factory=list)
    listed_out_of_scope: list[str] = field(default_factory=list)
    max_severity: str | None = None
    max_bounty: float | None = None
    bounty_currency: str | None = None
    payment_info: str | None = None
    safe_harbor: str | None = None
    disclosure_policy: str | None = None
    program_status: str | None = None
    last_updated: datetime | None = None
    security_email: str | None = None
    notes: str | None = None
    # Program-level access evidence; None means "use the platform default".
    platform_reputation_required: bool | None = None
    invite_required: bool | None = None
    application_required: bool | None = None
    private_program_supported: bool | None = None
    # Set only by a source that proves the program officially exists for us
    # (an invitation via a platform API, or the user's own seed entry).
    private_acknowledged: bool = False
    raw: dict = field(default_factory=dict)


def normalize(raw: dict, collector: str) -> NormalizedProgram:
    name = (raw.get("name") or raw.get("protocol_name") or raw.get("project_name") or "").strip()
    if not name:
        raise ValueError("program has no name")
    platform = str(raw.get("platform") or "unknown").strip().lower()
    program_url = raw.get("program_url") or raw.get("url")
    key_basis = raw.get("external_id") or program_url or name
    dedupe_key = f"{platform}:{hashlib.sha1(str(key_basis).lower().encode()).hexdigest()[:16]}"
    amount, currency = parse_money(raw.get("max_bounty"))
    email = raw.get("security_email")
    if email and not EMAIL_RE.fullmatch(str(email).strip()):
        email = None
    return NormalizedProgram(
        name=name,
        platform=platform,
        dedupe_key=dedupe_key,
        collector=collector,
        project_name=raw.get("project_name"),
        protocol_name=raw.get("protocol_name"),
        program_url=program_url,
        source_url=raw.get("source_url") or program_url,
        program_type=normalize_program_type(raw.get("program_type")),
        listed_scope=[s for s in (normalize_scope_item(i) for i in raw.get("listed_scope") or []) if s],
        listed_out_of_scope=[str(i) for i in raw.get("listed_out_of_scope") or []],
        max_severity=(str(raw["max_severity"]).lower() if raw.get("max_severity") else None),
        max_bounty=amount,
        bounty_currency=raw.get("bounty_currency") or currency,
        payment_info=raw.get("payment_info"),
        safe_harbor=raw.get("safe_harbor"),
        disclosure_policy=raw.get("disclosure_policy"),
        program_status=(str(raw["program_status"]).lower() if raw.get("program_status") else None),
        last_updated=parse_date(raw.get("last_updated")),
        security_email=email.strip() if email else None,
        notes=raw.get("notes"),
        platform_reputation_required=raw.get("platform_reputation_required"),
        invite_required=raw.get("invite_required"),
        application_required=raw.get("application_required"),
        private_program_supported=raw.get("private_program_supported"),
        private_acknowledged=bool(raw.get("private_acknowledged")),
        raw=raw,
    )
