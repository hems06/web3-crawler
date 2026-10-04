"""Optional ChatGPT (OpenAI) extraction for discovery.

When OPENAI_API_KEY is set, collectors send the text of public program and
security-policy pages to the model and ask for structured program details
(type, bounty, scope, contacts, private/invite signals). The model only
fills discovery fields. It never changes authorization, scope confirmation
or the research gate, and every value it returns is checked against the
page text before it is used, so it cannot invent contacts or contracts.
"""

from __future__ import annotations

import json
import logging
import re

import httpx

from .config import Settings, get_settings

log = logging.getLogger("crawler.llm")

MAX_CHARS = 12000

SYSTEM_PROMPT = """You extract facts about a bug bounty or vulnerability disclosure program from a public web page.
Return only a JSON object with these keys (use null or [] when the page does not say):
program_type: one of "public", "private", "invite_only", "vdp", "unknown"
max_bounty: string as written on the page, e.g. "$250,000" or "100k USDC"
max_severity: "critical" | "high" | "medium" | "low" | null
payment_info: currency/chain of payouts
security_email: an email address shown on the page for security reports
submission_url: URL where reports are submitted
in_scope: list of {"type": "domain"|"contract"|"repository"|"api", "value": "...", "chain": "..."|null}
out_of_scope: list of strings
safe_harbor: short quote or null
disclosure_policy: short summary or null
invite_required: true/false/null
application_required: true/false/null
private_signals: list of short quotes showing the program is private, invite-only or application-based
Only report what the page states. Do not guess."""


class LLMUnavailable(RuntimeError):
    pass


def enabled(settings: Settings | None = None) -> bool:
    return bool((settings or get_settings()).openai_api_key)


def _chat(text: str, url: str, settings: Settings, client: httpx.Client | None = None) -> dict:
    client = client or httpx.Client(timeout=60)
    resp = client.post(
        f"{settings.openai_base_url.rstrip('/')}/chat/completions",
        headers={"Authorization": f"Bearer {settings.openai_api_key}"},
        json={
            "model": settings.openai_model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"URL: {url}\n\nPAGE TEXT:\n{text[:MAX_CHARS]}"},
            ],
        },
    )
    resp.raise_for_status()
    content = resp.json()["choices"][0]["message"]["content"]
    return json.loads(content)


def _norm(s: str) -> str:
    return re.sub(r"\s+", "", s or "").lower()


def validate(data: dict, page_text: str) -> dict:
    """Keep only values that are grounded in the page text."""
    page = _norm(page_text)
    out: dict = {}
    ptype = str(data.get("program_type") or "").lower()
    if ptype in {"public", "private", "invite_only", "vdp", "unknown"}:
        out["program_type"] = ptype
    for key in ("max_bounty", "payment_info", "safe_harbor", "disclosure_policy"):
        if isinstance(data.get(key), str) and data[key].strip():
            out[key] = data[key].strip()[:1000]
    if str(data.get("max_severity") or "").lower() in {"critical", "high", "medium", "low"}:
        out["max_severity"] = data["max_severity"].lower()
    email = data.get("security_email")
    if isinstance(email, str) and _norm(email) and _norm(email) in page:
        out["security_email"] = email.strip()
    scope = []
    for item in data.get("in_scope") or []:
        if not isinstance(item, dict) or not item.get("value"):
            continue
        value = str(item["value"]).strip()
        if _norm(value) not in page:  # must appear on the page
            continue
        if item.get("type") not in {"domain", "contract", "repository", "api"}:
            continue
        scope.append({k: item[k] for k in ("type", "value", "chain") if item.get(k)})
    if scope:
        out["listed_scope"] = scope
    oos = [str(x)[:200] for x in data.get("out_of_scope") or [] if isinstance(x, (str, int))]
    if oos:
        out["listed_out_of_scope"] = oos
    for key in ("invite_required", "application_required"):
        if isinstance(data.get(key), bool):
            out[key] = data[key]
    signals = [str(x)[:300] for x in data.get("private_signals") or [] if isinstance(x, str)]
    if signals:
        out["private_signals"] = signals
    return out


def extract_program(page_text: str, url: str, settings: Settings | None = None, client: httpx.Client | None = None) -> dict:
    """Ask the model for program details. Returns {} on any failure."""
    settings = settings or get_settings()
    if not enabled(settings):
        return {}
    try:
        return validate(_chat(page_text, url, settings, client), page_text)
    except Exception as exc:  # noqa: BLE001 - extraction is best effort
        log.warning("LLM extraction failed for %s: %s", url, exc)
        return {}


def merge(raw: dict, extracted: dict) -> dict:
    """Fill a collector's raw program with model-extracted details.

    Values the collector already has win, except for program type and scope
    where the model's reading of the page is usually better than keywords.
    """
    if not extracted:
        return raw
    out = dict(raw)
    signals = extracted.pop("private_signals", [])
    for key, value in extracted.items():
        if key in ("program_type", "listed_scope", "listed_out_of_scope") or not out.get(key):
            if key == "program_type" and value == "unknown" and out.get("program_type"):
                continue
            out[key] = value
    if signals:
        out["notes"] = (out.get("notes") or "") + " Private signals: " + " | ".join(signals)
    out["extracted_by"] = "openai"
    return out
