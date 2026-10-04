"""Public bug bounty listings from bounty-targets-data.

https://github.com/arkadiyt/bounty-targets-data aggregates the public
program directories of HackerOne, Bugcrowd, Intigriti, YesWeHack and
Federacy into one JSON file per platform. Reading those files gives real,
publicly listed programs without crawling the platforms themselves. Only
Web3 programs are kept.
"""

from __future__ import annotations

import json
import logging
import re

from ..scope.engine import ADDRESS_RE, REPO_RE
from .base import Collector

log = logging.getLogger("crawler.collectors.bounty_targets")

ADDR_INLINE = re.compile(r"0x[a-fA-F0-9]{40}")
WEB3_TYPES = {"smart_contract", "blockchain", "smart-contract", "smart contract"}


def _scope_item(identifier: str, raw_type: str) -> dict | None:
    ident = (identifier or "").strip()
    t = (raw_type or "").lower()
    if not ident:
        return None
    if ADDRESS_RE.match(ident):
        return {"type": "contract", "value": ident}
    if REPO_RE.match(ident):
        return {"type": "repository", "value": ident}
    if t in ("api",) and "://" in ident:
        return {"type": "api", "value": ident}
    if t in ("url", "website", "web-application", "wildcard", "api", "other") and (
        "://" in ident or re.match(r"^(\*\.)?[a-z0-9.-]+\.[a-z]{2,}$", ident, re.I)
    ):
        host = ident.split("://", 1)[-1].split("/", 1)[0].lower()
        return {"type": "domain", "value": host}
    return None


def _scopes(entries: list[dict], id_keys: tuple[str, ...], type_keys: tuple[str, ...]) -> list[dict]:
    out = []
    for e in entries or []:
        ident = next((e.get(k) for k in id_keys if e.get(k)), None)
        raw_type = next((e.get(k) for k in type_keys if e.get(k)), "")
        item = _scope_item(str(ident or ""), str(raw_type))
        if item and item not in out:
            out.append(item)
    return out


def is_web3(entry: dict, keywords: list[str]) -> bool:
    targets = entry.get("targets") or {}
    types = {
        str(t.get("asset_type") or t.get("type") or "").lower()
        for t in targets.get("in_scope", [])
    }
    if types & WEB3_TYPES or ADDR_INLINE.search(json.dumps(targets)):
        return True
    text = " ".join(str(entry.get(k) or "") for k in ("name", "website", "handle", "company_handle"))
    for k in keywords:
        k = str(k)
        pattern = re.escape(k.rstrip("*")).replace(r"\ ", r"[\s_-]?") + (r"\w*" if k.endswith("*") else "")
        if re.search(r"\b" + pattern + r"\b", text, re.I):
            return True
    return False


def from_hackerone(e: dict) -> dict:
    t = e.get("targets") or {}
    bounty = bool(e.get("offers_bounties"))
    sev = [s.get("max_severity") for s in t.get("in_scope", []) if s.get("max_severity")]
    return {
        "name": e.get("name") or e.get("handle"),
        "platform": "hackerone",
        "external_id": f"h1:{e.get('handle')}",
        "program_url": e.get("url"),
        "program_type": "public" if bounty else "vdp",
        "listed_scope": _scopes(t.get("in_scope"), ("asset_identifier",), ("asset_type",)),
        "listed_out_of_scope": [i["value"] for i in _scopes(t.get("out_of_scope"), ("asset_identifier",), ("asset_type",))],
        "max_severity": next((s for s in ("critical", "high", "medium", "low") if s in sev), None),
        "program_status": "active" if e.get("submission_state") == "open" else e.get("submission_state"),
        "notes": ("offers bounties" if bounty else "no monetary rewards") + (f"; website {e['website']}" if e.get("website") else ""),
        # A publicly listed program does not need reputation or an invite.
        "platform_reputation_required": False,
        "invite_required": False,
    }


def from_bugcrowd(e: dict) -> dict:
    t = e.get("targets") or {}
    payout = e.get("max_payout")
    return {
        "name": (e.get("name") or "").strip(),
        "platform": "bugcrowd",
        "external_id": f"bc:{e.get('url')}",
        "program_url": e.get("url"),
        "program_type": "public" if payout else "vdp",
        "listed_scope": _scopes(t.get("in_scope"), ("uri", "target"), ("type",)),
        "listed_out_of_scope": [i["value"] for i in _scopes(t.get("out_of_scope"), ("uri", "target"), ("type",))],
        "max_bounty": payout,
        "safe_harbor": e.get("safe_harbor"),
        "platform_reputation_required": False,
        "invite_required": False,
    }


def from_intigriti(e: dict) -> dict:
    t = e.get("targets") or {}
    level = str(e.get("confidentiality_level") or "").lower()
    mb = e.get("max_bounty") or {}
    application = level == "application"
    return {
        "name": e.get("name"),
        "platform": "intigriti",
        "external_id": f"ig:{e.get('id')}",
        "program_url": e.get("url"),
        "program_type": "private" if application else ("public" if mb.get("value") else "vdp"),
        "listed_scope": _scopes(t.get("in_scope"), ("endpoint",), ("type",)),
        "listed_out_of_scope": [i["value"] for i in _scopes(t.get("out_of_scope"), ("endpoint",), ("type",))],
        "max_bounty": mb.get("value"),
        "bounty_currency": mb.get("currency"),
        "program_status": e.get("status"),
        "notes": f"confidentiality: {level}" + ("; apply to participate" if application else ""),
        "platform_reputation_required": False,
        "invite_required": False,
        "application_required": application,
    }


def from_yeswehack(e: dict) -> dict:
    t = e.get("targets") or {}
    return {
        "name": e.get("name"),
        "platform": "yeswehack",
        "external_id": f"ywh:{e.get('id')}",
        "program_url": f"https://yeswehack.com/programs/{e.get('id')}",
        "program_type": "public" if e.get("public") else "private",
        "listed_scope": _scopes(t.get("in_scope"), ("target",), ("type",)),
        "listed_out_of_scope": [i["value"] for i in _scopes(t.get("out_of_scope"), ("target",), ("type",))],
        "max_bounty": e.get("max_bounty"),
        "bounty_currency": "EUR" if e.get("max_bounty") else None,
        "program_status": "disabled" if e.get("disabled") else "active",
        "platform_reputation_required": False,
        "invite_required": False,
    }


def from_federacy(e: dict) -> dict:
    t = e.get("targets") or {}
    return {
        "name": e.get("name"),
        "platform": "federacy",
        "external_id": f"fed:{e.get('id')}",
        "program_url": e.get("url"),
        "program_type": "public" if e.get("offers_awards") else "vdp",
        "listed_scope": _scopes(t.get("in_scope"), ("target",), ("type",)),
        "listed_out_of_scope": [i["value"] for i in _scopes(t.get("out_of_scope"), ("target",), ("type",))],
    }


CONVERTERS = {
    "hackerone": from_hackerone,
    "bugcrowd": from_bugcrowd,
    "intigriti": from_intigriti,
    "yeswehack": from_yeswehack,
    "federacy": from_federacy,
}


class BountyTargetsCollector(Collector):
    name = "bounty_targets"

    def config(self) -> dict:
        return self.settings.load_yaml("sources.yaml").get("bounty_targets") or {}

    def enabled(self) -> bool:
        return bool(self.config().get("enabled", False))

    def collect(self):
        cfg = self.config()
        keywords = cfg.get("web3_keywords") or []
        for platform in cfg.get("platforms") or []:
            convert = CONVERTERS.get(platform)
            if convert is None:
                continue
            url = f"{cfg['base_url'].rstrip('/')}/{platform}_data.json"
            try:
                resp = self.fetcher.get(url)
                resp.raise_for_status()
                entries = resp.json()
            except Exception as exc:  # noqa: BLE001 - one platform failing must not stop the rest
                log.warning("could not read %s: %s", url, exc)
                continue
            for entry in entries:
                if is_web3(entry, keywords):
                    raw = convert(entry)
                    raw["source_url"] = url
                    yield raw
