"""Web3 protocols from DefiLlama, checked for a published security contact.

DefiLlama's public protocol list (https://api.llama.fi/protocols) gives the
largest Web3 protocols with their websites. For each website the collector
reads the RFC 9116 security.txt, which is the project's own statement of how
to reach its security team. Protocols without one are skipped: there is no
published channel to ask for authorization.
"""

from __future__ import annotations

import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .. import llm
from ..normalizer import EMAIL_RE
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


SECURITY_LINK_RE = re.compile(r"bug[\s-]?bounty|security|responsible[\s-]disclosure|vulnerability|audits?\b", re.I)


def security_links(html: str, base_url: str) -> list[str]:
    """Links on a homepage that look like its security or bug bounty page."""
    soup = BeautifulSoup(html, "html.parser")
    scored = []
    for a in soup.find_all("a", href=True):
        href = urljoin(base_url, a["href"].strip())
        text = " ".join(a.get_text(" ").split())
        if not href.startswith("https://"):
            continue
        hay = f"{text} {urlparse(href).path}"
        if not SECURITY_LINK_RE.search(hay):
            continue
        score = 3 if re.search(r"bounty", hay, re.I) else 2 if re.search(r"security|disclosure", hay, re.I) else 1
        if platform_for([href]):
            score += 2
        if href not in [h for _, h in scored]:
            scored.append((score, href))
    return [h for _, h in sorted(scored, key=lambda x: -x[0])]


def page_raw(protocol: dict, url: str, text: str) -> dict | None:
    """A candidate from a protocol's own security page, or None when the page
    gives no published way to reach the security team."""
    emails = [e for e in EMAIL_RE.findall(text) if re.search(r"security|bounty|disclos|bugs?@|whitehat", e, re.I)]
    platform = platform_for([url])
    if not emails and not platform:
        return None
    raw = {
        "name": protocol.get("name") or protocol["_host"],
        "project_name": protocol.get("name"),
        "protocol_name": protocol.get("name"),
        "external_id": f"defillama:{protocol.get('slug') or protocol['_host']}",
        "platform": platform or "direct",
        "program_url": url,
        "source_url": url,
        "program_type": "public" if platform else "unknown",
        "security_email": emails[0] if emails else None,
        "notes": f"Security page found from the homepage of {protocol['_host']}.",
        "raw_defillama": {k: protocol.get(k) for k in ("slug", "category", "chains", "github", "twitter", "tvl")},
    }
    return raw


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
            self.note("protocol list from DefiLlama")
            resp = self.fetcher.get(cfg.get("protocols_url", "https://api.llama.fi/protocols"), deadline=120)
            resp.raise_for_status()
            protocols = resp.json()
        except Exception as exc:  # noqa: BLE001
            log.warning("could not read DefiLlama protocols: %s", exc)
            return
        chosen = select_protocols(
            protocols, int(cfg.get("top_n", 75)), float(cfg.get("min_tvl_usd", 0)), cfg.get("exclude_categories") or []
        )
        self._llm_budget = self.settings.llm_max_pages
        self._budget_lock = threading.Lock()
        self._stop = threading.Event()
        homepage_fallback = cfg.get("homepage_fallback", True)
        # Each protocol is a different site, so several are read at once;
        # requests to any one site stay rate limited by the fetcher.
        workers = max(1, int(cfg.get("workers", 8)))
        pool = ThreadPoolExecutor(max_workers=workers)
        futures = {pool.submit(self._one, p, homepage_fallback): p for p in chosen}
        try:
            for done, fut in enumerate(as_completed(futures), 1):
                self.note(f"protocols {done}/{len(chosen)}: {futures[fut]['_host']}")
                try:
                    raw = fut.result()
                except Exception as exc:  # noqa: BLE001 - one site failing must not stop the rest
                    log.info("skipped %s: %s", futures[fut]["_host"], exc)
                    continue
                if raw is not None:
                    yield raw
        finally:
            # Ctrl+C or an early stop: don't start the remaining sites.
            self._stop.set()
            pool.shutdown(wait=False, cancel_futures=True)

    def _one(self, protocol: dict, homepage_fallback: bool) -> dict | None:
        if self._stop.is_set():
            return None
        raw = self._from_security_txt(protocol)
        if raw is None and homepage_fallback and not self._stop.is_set():
            raw = self._from_homepage(protocol)
        return raw

    def _use_llm(self) -> bool:
        with self._budget_lock:
            if llm.enabled(self.settings) and self._llm_budget > 0:
                self._llm_budget -= 1
                return True
            return False

    def _from_security_txt(self, protocol: dict) -> dict | None:
        for path in ("/.well-known/security.txt", "/security.txt"):
            url = f"https://{protocol['_host']}{path}"
            try:
                r = self.fetcher.get(url)
            except (FetchRefused, Exception):  # noqa: BLE001
                continue
            if r.status_code == 200 and "contact:" in r.text.lower() and "<html" not in r.text[:500].lower():
                fields = parse_security_txt(r.text)
                raw = to_raw(protocol, fields, url)
                if fields.get("policy") and self._use_llm():
                    raw = self._enrich_from_policy(raw, fields["policy"][0])
                return raw
        return None

    def _from_homepage(self, protocol: dict) -> dict | None:
        """No security.txt: follow the homepage's security / bug bounty link."""
        home = f"https://{protocol['_host']}/"
        try:
            r = self.fetcher.get(home)
        except (FetchRefused, Exception):  # noqa: BLE001
            return None
        if r.status_code != 200 or "html" not in r.headers.get("content-type", "html"):
            return None
        for link in security_links(r.text, home)[:2]:
            if self._stop.is_set():
                return None
            if platform_for([link]):
                # A bounty platform listing: record it without fetching the platform.
                return page_raw(protocol, link, "")
            try:
                page = self.fetcher.get(link)
            except (FetchRefused, Exception):  # noqa: BLE001
                continue
            if page.status_code != 200 or "html" not in page.headers.get("content-type", "html"):
                continue
            text = page_text(page.text)
            raw = page_raw(protocol, link, text)
            if self._use_llm():
                extracted = llm.extract_program(text, link, self.settings)
                if raw is None and extracted.get("security_email"):
                    raw = page_raw(protocol, link, extracted["security_email"])
                if raw is not None:
                    raw = llm.merge(raw, extracted)
            if raw is not None:
                return raw
        return None

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
