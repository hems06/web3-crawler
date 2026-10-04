"""Web3 protocols from DefiLlama, checked for a published security contact.

DefiLlama's public protocol list (https://api.llama.fi/protocols) gives the
largest Web3 protocols with their websites. For each website the collector
reads the RFC 9116 security.txt, which is the project's own statement of how
to reach its security team. Protocols without one are skipped: there is no
published channel to ask for authorization.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from .. import llm
from .base import Collector, FetchRefused
from .program_page import page_text
from .security_txt import parse_security_txt, to_program

log = logging.getLogger("crawler.collectors.defillama")

PLATFORM_HOSTS = {
    "immunefi.com": "immunefi",
    "hackerone.com": "hackerone",
    "bugcrowd.com": "bugcrowd",
    "hackenproof.com": "hackenproof",
    "cantina.xyz": "cantina",
    "intigriti.com": "intigriti",
    "yeswehack.com": "yeswehack",
}


def platform_for(urls: list[str]) -> str | None:
    for url in urls:
        host = (urlparse(url).hostname or "").lower()
        for suffix, slug in PLATFORM_HOSTS.items():
            if host == suffix or host.endswith("." + suffix):
                return slug
    return None


def select_protocols(protocols: list[dict], top_n: int, min_tvl: float, exclude_categories: list[str]) -> list[dict]:
    excluded = {c.lower() for c in exclude_categories}
    seen_hosts: set[str] = set()
    out = []
    ranked = sorted(protocols, key=lambda p: p.get("tvl") or 0, reverse=True)
    for p in ranked:
        if (p.get("tvl") or 0) < min_tvl or str(p.get("category") or "").lower() in excluded:
            continue
        host = (urlparse(p.get("url") or "").hostname or "").lower()
        if not host:
            continue
        host = host[4:] if host.startswith("www.") else host
        if host in seen_hosts:  # protocol versions often share a website
            continue
        seen_hosts.add(host)
        out.append({**p, "_host": host})
        if len(out) >= top_n:
            break
    return out


def to_raw(protocol: dict, fields: dict, security_txt_url: str) -> dict:
    raw = to_program(protocol["_host"], fields, security_txt_url)
    links = fields.get("policy", []) + fields.get("contact", [])
    platform = platform_for(links)
    raw.update(
        {
            "name": protocol.get("name") or protocol["_host"],
            "project_name": protocol.get("name"),
            "protocol_name": protocol.get("name"),
            "external_id": f"defillama:{protocol.get('slug') or protocol['_host']}",
        }
    )
    if platform:
        # The project points researchers at a platform listing.
        raw["platform"] = platform
        raw["program_type"] = "public"
    chains = ", ".join(protocol.get("chains") or [])
    raw["notes"] = (
        f"{raw.get('notes', '')}. DefiLlama: {protocol.get('category') or 'protocol'}"
        + (f" on {chains}" if chains else "")
        + ". Published security contact, no public bounty listing found: contact the security team to ask."
        if not platform
        else f"{raw.get('notes', '')}. Security policy points to {platform}."
    )
    raw["raw_defillama"] = {k: protocol.get(k) for k in ("slug", "category", "chains", "github", "twitter", "tvl")}
    return raw


class DefiLlamaSecurityTxtCollector(Collector):
    name = "defillama_security_txt"

    def config(self) -> dict:
        return self.settings.load_yaml("sources.yaml").get("defillama_security_txt") or {}

    def enabled(self) -> bool:
        return bool(self.config().get("enabled", False))

    def collect(self):
        cfg = self.config()
        try:
            resp = self.fetcher.get(cfg.get("protocols_url", "https://api.llama.fi/protocols"))
            resp.raise_for_status()
            protocols = resp.json()
        except Exception as exc:  # noqa: BLE001
            log.warning("could not read DefiLlama protocols: %s", exc)
            return
        chosen = select_protocols(
            protocols, int(cfg.get("top_n", 75)), float(cfg.get("min_tvl_usd", 0)), cfg.get("exclude_categories") or []
        )
        llm_budget = self.settings.llm_max_pages
        for protocol in chosen:
            for path in ("/.well-known/security.txt", "/security.txt"):
                url = f"https://{protocol['_host']}{path}"
                try:
                    r = self.fetcher.get(url)
                except (FetchRefused, Exception):  # noqa: BLE001
                    continue
                if r.status_code == 200 and "contact:" in r.text.lower() and "<html" not in r.text[:500].lower():
                    fields = parse_security_txt(r.text)
                    raw = to_raw(protocol, fields, url)
                    if llm.enabled(self.settings) and llm_budget > 0 and fields.get("policy"):
                        llm_budget -= 1
                        raw = self._enrich_from_policy(raw, fields["policy"][0])
                    yield raw
                    break

    def _enrich_from_policy(self, raw: dict, policy_url: str) -> dict:
        """Read the security policy page the project links and let the model
        pull out bounty, scope and private-program details."""
        if not policy_url.startswith("https://"):
            return raw
        try:
            r = self.fetcher.get(policy_url)
        except Exception:  # noqa: BLE001
            return raw
        if r.status_code != 200 or "html" not in r.headers.get("content-type", "html"):
            return raw
        return llm.merge(raw, llm.extract_program(page_text(r.text), policy_url, self.settings))
