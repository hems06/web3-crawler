"""Configurable opportunity score (0..100).

Inputs are things that make a program a good, legitimate target to ask
about. Researcher reputation, submission counts, leaderboards, popularity and
historical payouts are deliberately not used.
"""

from __future__ import annotations

import math
from datetime import timedelta

from .config import Settings, get_settings
from .enums import AssetType, AuthState as S, BountyStatus, Classification, ScopeStatus
from .models import as_utc, utcnow

AUTH_CONFIDENCE = {
    S.READY_FOR_RESEARCH: 1.0,
    S.BOUNTY_CONFIRMED: 1.0,
    S.SCOPE_CONFIRMED: 0.9,
    S.BOUNTY_NOT_AVAILABLE: 0.7,
    S.AUTHORIZED: 0.8,
    S.SCOPE_UNCLEAR: 0.5,
    S.AWAITING_RESPONSE: 0.4,
    S.AUTHORIZATION_REQUESTED: 0.35,
    S.PRIVATE_CANDIDATE: 0.3,
    S.DISCOVERED: 0.2,
    S.NO_RESPONSE: 0.1,
    S.VDP_ONLY: 0.1,
    S.EXPIRED_AUTHORIZATION: 0.1,
    S.NOT_AUTHORIZED: 0.0,
    S.DECLINED: 0.0,
}
SCOPE_CLARITY = {
    ScopeStatus.CONFIRMED: 1.0,
    ScopeStatus.LISTED: 0.5,
    ScopeStatus.UNCLEAR: 0.2,
    ScopeStatus.UNKNOWN: 0.0,
}
BOUNTY = {
    BountyStatus.CONFIRMED: 1.0,
    BountyStatus.LISTED: 0.6,
    BountyStatus.UNKNOWN: 0.3,
    BountyStatus.NOT_AVAILABLE: 0.0,
}
# Lower expected competition scores higher.
COMPETITION = {
    Classification.PRIVATE_CONFIRMED: 1.0,
    Classification.PRIVATE_POSSIBLE: 0.8,
    Classification.UNKNOWN: 0.5,
    Classification.VDP_ONLY: 0.4,
    Classification.PUBLIC: 0.2,
}


def components(program, cfg: dict) -> dict[str, float]:
    scope_items = [r for r in program.scope_rules if r.in_scope] or [
        s for s in (program.listed_scope or [])
    ]
    n_scope = len(scope_items)
    types = {getattr(s, "rule_type", None) or s.get("type") for s in scope_items}
    has_contracts = AssetType.CONTRACT.value in types

    cap = float(cfg.get("max_bounty_cap_usd", 1_000_000))
    bounty = program.max_bounty or 0
    max_bounty = min(1.0, math.log10(1 + bounty) / math.log10(1 + cap)) if bounty else 0.0

    updated = as_utc(program.source_last_updated) or as_utc(program.last_seen_at)
    fresh_days, stale_days = cfg.get("fresh_days", 30), cfg.get("stale_days", 365)
    if updated is None:
        freshness = 0.3
    else:
        age = (utcnow() - updated) / timedelta(days=1)
        freshness = 1.0 if age <= fresh_days else max(0.0, 1 - (age - fresh_days) / (stale_days - fresh_days))

    quality_types = {AssetType.CONTRACT.value, AssetType.REPOSITORY.value}
    asset_quality = min(1.0, len(types & quality_types) / 2 + (0.25 if program.security_email else 0))

    return {
        "authorization_status": AUTH_CONFIDENCE.get(S(program.authorization_status), 0.0),
        "scope_clarity": SCOPE_CLARITY.get(ScopeStatus(program.scope_status), 0.0),
        "bounty_available": BOUNTY.get(BountyStatus(program.bounty_status), 0.0),
        "max_bounty": max_bounty,
        "program_freshness": freshness,
        "asset_quality": asset_quality,
        "smart_contract_availability": 1.0 if has_contracts else 0.0,
        "scope_size": min(1.0, n_scope / float(cfg.get("scope_size_cap", 25))),
        "competition_level": COMPETITION.get(Classification(program.classification), 0.5),
    }


def score(program, settings: Settings | None = None, cfg: dict | None = None) -> float:
    cfg = cfg if cfg is not None else (settings or get_settings()).load_yaml("scoring.yaml")
    weights = cfg.get("weights") or {}
    parts = components(program, cfg)
    total_w = sum(float(weights.get(k, 0)) for k in parts)
    if total_w <= 0:
        return 0.0
    value = sum(parts[k] * float(weights.get(k, 0)) for k in parts) / total_w
    return round(value * 100, 1)
