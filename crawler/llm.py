"""Optional ChatGPT (OpenAI) extraction for discovery.

When OPENAI_API_KEY is set, collectors send the text of public program and
security-policy pages to the model and ask for structured program details
(type, bounty, scope, contacts, private/invite signals). The model only
fills discovery fields. It never changes authorization, scope confirmation
or the research gate, and every value it returns is checked against the
page text before it is used, so it cannot invent contacts or contracts.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path

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


# Rate limits are retried with backoff, honouring Retry-After, up to this
# many times per call and this many seconds of waiting per call.
MAX_RETRIES = 3
MAX_WAIT = 30.0
# After this many failed calls in a row, the model is turned off for the run.
MAX_CONSECUTIVE_FAILURES = 3

_state = {"disabled": None, "failures": 0}
_sleep = time.sleep  # replaced in tests


def reset() -> None:
    """Start a new run with the model on (if a key is set)."""
    _state["disabled"] = None
    _state["failures"] = 0


def disable(reason: str) -> None:
    """Turn the model off for the rest of this run, saying why once."""
    if _state["disabled"] is None:
        _state["disabled"] = reason
        log.warning("ChatGPT turned off for the rest of this run: %s. Crawling continues without it.", reason)


def disabled_reason() -> str | None:
    return _state["disabled"]


def enabled(settings: Settings | None = None) -> bool:
    return bool((settings or get_settings()).openai_api_key) and _state["disabled"] is None


def _error_code(resp: httpx.Response) -> str:
    try:
        err = resp.json().get("error") or {}
        return str(err.get("code") or err.get("type") or "")
    except Exception:  # noqa: BLE001
        return ""


def _retry_after(resp: httpx.Response, attempt: int) -> float:
    for header in ("retry-after", "x-ratelimit-reset-requests", "x-ratelimit-reset-tokens"):
        value = resp.headers.get(header, "")
        m = re.fullmatch(r"\s*([\d.]+)\s*(ms|s)?\s*", value)
        if m:
            secs = float(m.group(1)) / (1000 if m.group(2) == "ms" else 1)
            return min(max(secs, 0.5), MAX_WAIT)
    return min(2.0 * (2**attempt), MAX_WAIT)


def _failed(exc: Exception) -> None:
    """Count a failed call; turn the model off when it keeps failing."""
    _state["failures"] += 1
    if isinstance(exc, LLMUnavailable):
        disable(str(exc))
    elif _state["failures"] >= MAX_CONSECUTIVE_FAILURES:
        disable(f"{_state['failures']} requests in a row failed (last: {_short(exc)})")


def _short(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}"
    return str(exc).splitlines()[0][:120] if str(exc) else type(exc).__name__


CLASSIFY_PROMPT = """You decide which bug bounty programs belong to Web3 / crypto organisations
(blockchains, DeFi protocols, exchanges, wallets, NFT platforms, bridges, L2s, crypto infrastructure).
You get a JSON list of programs, each with an "i" index, a name, a website and some in-scope targets.
Return only {"web3": [indexes of the Web3 programs]}. Leave out anything you are unsure about."""

CLASSIFY_BATCH = 80

# Sentences around these words carry the program details; the rest of a page
# (navigation, marketing) is dropped before it is sent to the model.
FOCUS_RE = re.compile(
    r"bounty|bounties|reward|payout|scope|severity|critical|security|vulnerab|disclos|safe harbo|"
    r"invite|private|apply|contract|0x[a-f0-9]{6}|github\.com|report|submit|@|usdc|usdt|\$",
    re.I,
)


def focus_text(text: str, limit: int = MAX_CHARS) -> str:
    """Shorten a page to the parts that describe the program.

    Short pages are returned as is. Longer ones keep each sentence that
    mentions bounty, scope, contacts or contracts, plus its neighbours, so
    fewer tokens go to the model without losing the facts it needs.
    """
    if len(text) <= limit:
        return text
    parts = re.split(r"(?<=[.!?])\s+|\s{2,}| \| ", text)
    keep = [False] * len(parts)
    for i, part in enumerate(parts):
        if FOCUS_RE.search(part):
            for j in (i - 1, i, i + 1):
                if 0 <= j < len(parts):
                    keep[j] = True
    out = " ".join(p for p, k in zip(parts, keep) if k)
    return (out or text)[:limit]


# ------------------------------------------------------------------- cache
def cache_path(settings: Settings) -> Path:
    if settings.llm_cache_file:
        return Path(settings.llm_cache_file).expanduser()
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "web3-crawler" / "llm.json"


def _cache_load(settings: Settings) -> dict:
    try:
        return json.loads(cache_path(settings).read_text())
    except (OSError, ValueError):
        return {}


def _cache_put(settings: Settings, key: str, value) -> None:
    data = _cache_load(settings)
    data[key] = value
    _cache_save(settings, data)


def _cache_save(settings: Settings, data: dict) -> None:
    p = cache_path(settings)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        tmp.replace(p)
    except OSError as exc:
        log.debug("LLM cache write failed: %s", exc)


def _key(settings: Settings, *parts: str) -> str:
    h = hashlib.sha256()
    for part in (settings.openai_model, *parts):
        h.update(part.encode())
        h.update(b"\0")
    return h.hexdigest()


def _post(messages: list[dict], settings: Settings, client: httpx.Client | None = None) -> dict:
    """One chat completion. Rate limits are retried; a quota or key problem
    raises LLMUnavailable so callers can turn the model off for the run."""
    client = client or httpx.Client(timeout=60)
    for attempt in range(MAX_RETRIES + 1):
        resp = client.post(
            f"{settings.openai_base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {settings.openai_api_key}"},
            json={
                "model": settings.openai_model,
                "temperature": 0,
                "response_format": {"type": "json_object"},
                "messages": messages,
            },
        )
        if resp.status_code == 429:
            if _error_code(resp) == "insufficient_quota":
                raise LLMUnavailable(
                    "the OpenAI account has no credit left (insufficient_quota); add credit or check the "
                    "monthly budget at https://platform.openai.com/settings/organization/billing"
                )
            if attempt < MAX_RETRIES:
                _sleep(_retry_after(resp, attempt))
                continue
            raise LLMUnavailable(
                "OpenAI kept rate limiting requests (429) after retries; try again later or use a higher-tier account"
            )
        if resp.status_code == 401:
            raise LLMUnavailable("the OpenAI API key was rejected (401); run `crawler setup` to enter it again")
        if resp.status_code == 404 and _error_code(resp) == "model_not_found":
            raise LLMUnavailable(f"model {settings.openai_model!r} is not available to this key; run `crawler setup`")
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        _state["failures"] = 0
        return json.loads(content)
    raise AssertionError("unreachable")


def _chat(text: str, url: str, settings: Settings, client: httpx.Client | None = None) -> dict:
    return _post(
        [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"URL: {url}\n\nPAGE TEXT:\n{focus_text(text)}"},
        ],
        settings,
        client,
    )


def check_key(settings: Settings, client: httpx.Client | None = None) -> None:
    """Raise if the API key or model is not accepted (lists models; no tokens used)."""
    client = client or httpx.Client(timeout=20)
    resp = client.get(
        f"{settings.openai_base_url.rstrip('/')}/models/{settings.openai_model}",
        headers={"Authorization": f"Bearer {settings.openai_api_key}"},
    )
    if resp.status_code == 401:
        raise LLMUnavailable("the API key was rejected")
    if resp.status_code == 404:
        raise LLMUnavailable(f"model {settings.openai_model!r} is not available to this key")
    resp.raise_for_status()


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
    key = _key(settings, "extract", SYSTEM_PROMPT, url, page_text)
    cached = _cache_load(settings).get(key)
    if isinstance(cached, dict):
        return validate(cached, page_text)
    try:
        data = _chat(page_text, url, settings, client)
    except Exception as exc:  # noqa: BLE001 - extraction is best effort
        log.info("LLM extraction failed for %s: %s", url, _short(exc))
        _failed(exc)
        return {}
    _cache_put(settings, key, data)
    return validate(data, page_text)


def classify_web3(items: list[dict], settings: Settings | None = None, client: httpx.Client | None = None) -> list[bool]:
    """Say which programs are Web3, in batches. Answers are cached per program.

    ``items`` are short descriptions ({"name", "website", "targets"}). Any
    item the model could not be asked about counts as not Web3.
    """
    settings = settings or get_settings()
    result = [False] * len(items)
    if not enabled(settings) or not items:
        return result
    cache = _cache_load(settings)
    keys = [_key(settings, "web3", CLASSIFY_PROMPT, json.dumps(it, sort_keys=True)) for it in items]
    todo = []
    for i, k in enumerate(keys):
        if isinstance(cache.get(k), bool):
            result[i] = cache[k]
        else:
            todo.append(i)
    for start in range(0, len(todo), CLASSIFY_BATCH):
        batch = todo[start : start + CLASSIFY_BATCH]
        payload = [{"i": n, **items[i]} for n, i in enumerate(batch)]
        try:
            data = _post(
                [
                    {"role": "system", "content": CLASSIFY_PROMPT},
                    {"role": "user", "content": json.dumps(payload)},
                ],
                settings,
                client,
            )
        except Exception as exc:  # noqa: BLE001
            log.info("LLM Web3 classification failed: %s", _short(exc))
            _failed(exc)
            break
        chosen = {n for n in data.get("web3") or [] if isinstance(n, int) and 0 <= n < len(batch)}
        for n, i in enumerate(batch):
            result[i] = n in chosen
            cache[keys[i]] = n in chosen
    if todo:
        _cache_save(settings, cache)
    return result


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
