"""HackerOne Hacker API collector.

Uses the official API with the researcher's own credentials. It lists the
programs that account can access, which includes private programs the
researcher was invited to; those are PRIVATE_CONFIRMED because the platform
itself acknowledges them. Nothing outside that list is guessed at.
"""

from __future__ import annotations

from .base import Collector

API = "https://api.hackerone.com/v1/hackers"


class HackerOneCollector(Collector):
    name = "hackerone"

    def enabled(self) -> bool:
        return bool(self.settings.hackerone_api_username and self.settings.hackerone_api_token)

    def _get(self, url: str, **params):
        resp = self.fetcher.get(
            url,
            check_robots=False,  # official API, authenticated
            params=params,
            auth=(self.settings.hackerone_api_username, self.settings.hackerone_api_token),
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        return resp.json()

    def collect(self):
        if not self.enabled():
            return
        url = f"{API}/programs"
        while url:
            data = self._get(url, **{"page[size]": 100})
            for item in data.get("data", []):
                yield self.to_program(item, self._scopes(item))
            url = (data.get("links") or {}).get("next")

    def _scopes(self, item: dict) -> list[dict]:
        handle = item.get("attributes", {}).get("handle")
        if not handle:
            return []
        try:
            data = self._get(f"{API}/programs/{handle}/structured_scopes")
        except Exception:  # noqa: BLE001
            return []
        return [d.get("attributes", {}) for d in data.get("data", [])]

    @staticmethod
    def to_program(item: dict, scopes: list[dict]) -> dict:
        a = item.get("attributes", {})
        handle = a.get("handle")
        state = (a.get("state") or "").lower()
        private = state == "soft_launched"
        in_scope, out_scope = [], []
        type_map = {
            "url": "domain",
            "wildcard": "domain",
            "smart_contract": "contract",
            "source_code": "repository",
            "api": "api",
        }
        for s in scopes:
            ident = s.get("asset_identifier")
            if not ident:
                continue
            entry = {
                "value": ident,
                "type": type_map.get((s.get("asset_type") or "").lower()),
                "eligible_for_bounty": s.get("eligible_for_bounty"),
                "max_severity": s.get("max_severity"),
            }
            entry = {k: v for k, v in entry.items() if v is not None}
            (in_scope if s.get("eligible_for_submission", True) else out_scope).append(entry)
        return {
            "name": a.get("name") or handle,
            "platform": "hackerone",
            "external_id": f"h1:{handle}",
            "program_url": f"https://hackerone.com/{handle}",
            "program_type": "private" if private else ("public" if state == "public_mode" else "unknown"),
            "private_acknowledged": private,
            "invite_required": True if private else None,
            "listed_scope": in_scope,
            "listed_out_of_scope": [o["value"] for o in out_scope],
            "max_bounty": None,
            "program_status": "active" if a.get("submission_state") == "open" else a.get("submission_state"),
            "disclosure_policy": (a.get("policy") or "")[:4000] or None,
            "notes": "offers bounties" if a.get("offers_bounties") else None,
            "last_updated": a.get("started_accepting_at"),
        }
