"""Reads public security / bug bounty pages listed in config/watchlist.yaml
and pulls out what the page states about the program."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from ..normalizer import EMAIL_RE
from ..scope.engine import ADDRESS_RE
from .base import Collector, FetchRefused

ADDR_INLINE = re.compile(r"0x[a-fA-F0-9]{40}")
REPO_INLINE = re.compile(r"github\.com/[\w.-]+/[\w.-]+")
BOUNTY_INLINE = re.compile(r"(?:up to|maximum|max)[^$\d]{0,20}(\$\s?[\d,.]+\s?[kKmM]?|[\d,.]+\s?[kKmM]?\s?(?:USDC|USDT|USD))", re.I)
SEVERITY_INLINE = re.compile(r"\b(critical|high|medium|low)\b", re.I)


def extract_page(url: str, html: str, project: str | None = None) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = " ".join(soup.get_text(" ").split())
    lower = text.lower()
    title = (soup.title.string.strip() if soup.title and soup.title.string else None)
    emails = sorted({e for e in EMAIL_RE.findall(text) if "security" in e.lower() or "bounty" in e.lower()})
    bounty = BOUNTY_INLINE.search(text)
    severities = [s.lower() for s in SEVERITY_INLINE.findall(text)]
    max_sev = next((s for s in ("critical", "high", "medium", "low") if s in severities), None)
    scope = [{"type": "contract", "value": a.lower()} for a in sorted(set(ADDR_INLINE.findall(text))) if ADDRESS_RE.match(a)]
    scope += [{"type": "repository", "value": r} for r in sorted(set(REPO_INLINE.findall(text)))]
    if "invite-only" in lower or "invite only" in lower or "by invitation" in lower:
        ptype = "invite_only"
    elif "private program" in lower or "private bug bounty" in lower:
        ptype = "private"
    elif "vulnerability disclosure" in lower and not bounty:
        ptype = "vdp"
    elif "bug bounty" in lower:
        ptype = "public"
    else:
        ptype = "unknown"
    return {
        "name": project or title or urlparse(url).hostname,
        "project_name": project,
        "platform": "direct",
        "program_url": url,
        "source_url": url,
        "program_type": ptype,
        "listed_scope": scope,
        "max_bounty": bounty.group(1) if bounty else None,
        "max_severity": max_sev,
        "security_email": emails[0] if emails else None,
        "safe_harbor": "mentioned" if "safe harbor" in lower or "safe harbour" in lower else None,
        "application_required": True if re.search(r"\bapply (to|for)\b", lower) else None,
        "invite_required": True if ptype == "invite_only" else None,
        "description": text[:2000],
    }


class ProgramPageCollector(Collector):
    name = "program_page"

    def __init__(self, *args, pages: list[dict] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.pages = pages

    def collect(self):
        pages = self.pages
        if pages is None:
            pages = self.settings.load_yaml("watchlist.yaml").get("program_pages") or []
        for page in pages:
            url = page["url"] if isinstance(page, dict) else page
            try:
                resp = self.fetcher.get(url)
            except (FetchRefused, Exception):  # noqa: BLE001
                continue
            if resp.status_code == 200 and "html" in resp.headers.get("content-type", "html"):
                yield extract_page(url, resp.text, page.get("project") if isinstance(page, dict) else None)
