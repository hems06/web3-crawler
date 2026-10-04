"""RFC 9116 security.txt collector.

security.txt is the project's own published statement of how to reach its
security team, so it is a legitimate source for contacts and policy links.
"""

from __future__ import annotations

import re

from .base import Collector, FetchRefused

FIELD_RE = re.compile(r"^\s*([A-Za-z-]+)\s*:\s*(.+?)\s*$")


def parse_security_txt(text: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        m = FIELD_RE.match(line)
        if m:
            fields.setdefault(m.group(1).lower(), []).append(m.group(2))
    return fields


def to_program(domain: str, fields: dict[str, list[str]], url: str) -> dict:
    contacts = fields.get("contact", [])
    email = next((c[len("mailto:"):] for c in contacts if c.lower().startswith("mailto:")), None)
    if email is None:
        email = next((c for c in contacts if "@" in c and "://" not in c), None)
    policy = (fields.get("policy") or [None])[0]
    return {
        "name": domain,
        "project_name": domain,
        "platform": "direct",
        "program_url": policy or url,
        "source_url": url,
        "external_id": f"security.txt:{domain}",
        "program_type": "unknown",
        "security_email": email,
        "disclosure_policy": policy,
        "listed_scope": [],
        "notes": "Found via security.txt. Contacts: " + ", ".join(contacts),
        "last_updated": None,
        "raw_security_txt": fields,
    }


class SecurityTxtCollector(Collector):
    name = "security_txt"

    def __init__(self, *args, domains: list[str] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.domains = domains

    def collect(self):
        domains = self.domains
        if domains is None:
            domains = self.settings.load_yaml("watchlist.yaml").get("security_txt") or []
        for domain in domains:
            for path in ("/.well-known/security.txt", "/security.txt"):
                url = f"https://{domain}{path}"
                try:
                    resp = self.fetcher.get(url)
                except (FetchRefused, Exception):  # noqa: BLE001 - one bad domain must not stop the run
                    continue
                if resp.status_code == 200 and "contact:" in resp.text.lower() and "<html" not in resp.text[:500].lower():
                    yield to_program(domain, parse_security_txt(resp.text), url)
                    break
