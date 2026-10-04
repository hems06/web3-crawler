"""Scope engine: decides whether an asset is in, out of, or unknown to a
program's scope. Anything that does not match an explicit rule is
SCOPE_UNKNOWN, and SCOPE_UNKNOWN is never testable."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from .. import audit
from ..enums import AssetScope, AssetType, AuditEventType

ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
DOMAIN_RE = re.compile(
    r"^(\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$", re.I
)
REPO_RE = re.compile(r"^(?:https?://)?(?:www\.)?github\.com/([\w.-]+)(?:/([\w.*-]+))?/?", re.I)

KNOWN_CHAINS = {
    "ethereum": "Ethereum",
    "mainnet": "Ethereum",
    "eth": "Ethereum",
    "arbitrum": "Arbitrum",
    "arbitrum one": "Arbitrum",
    "optimism": "Optimism",
    "op mainnet": "Optimism",
    "base": "Base",
    "polygon": "Polygon",
    "matic": "Polygon",
    "bsc": "BNB Chain",
    "bnb chain": "BNB Chain",
    "bnb smart chain": "BNB Chain",
    "avalanche": "Avalanche",
    "avax": "Avalanche",
    "gnosis": "Gnosis",
    "zksync": "zkSync",
    "zksync era": "zkSync",
    "linea": "Linea",
    "scroll": "Scroll",
    "blast": "Blast",
    "mantle": "Mantle",
    "fantom": "Fantom",
    "sonic": "Sonic",
    "solana": "Solana",
    "sui": "Sui",
    "aptos": "Aptos",
    "starknet": "Starknet",
    "cosmos": "Cosmos",
    "near": "NEAR",
    "polkadot": "Polkadot",
}

# Out-of-scope categories that translate into prohibited research methods.
CATEGORY_METHODS = {
    "denial_of_service": ["denial_of_service"],
    "dos": ["denial_of_service"],
    "ddos": ["denial_of_service"],
    "social_engineering": ["social_engineering", "phishing"],
    "phishing": ["phishing"],
    "brute_force": ["brute_force"],
    "automated_scanning": ["active_scan"],
    "active_scanning": ["active_scan"],
    "mainnet_testing": ["exploit_live"],
}


def normalize_chain(value: str | None) -> str | None:
    if not value:
        return None
    key = value.strip().lower()
    return KNOWN_CHAINS.get(key, value.strip())


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        value = urlparse(value).hostname or value
    return value.rstrip(".").split(":")[0].split("/")[0]


def normalize_repo(value: str) -> str | None:
    m = REPO_RE.match(value.strip())
    if not m:
        return None
    owner, repo = m.group(1).lower(), (m.group(2) or "").lower()
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"github.com/{owner}/{repo}" if repo else f"github.com/{owner}"


def guess_asset_type(identifier: str) -> AssetType:
    value = identifier.strip()
    if ADDRESS_RE.match(value):
        return AssetType.CONTRACT
    if REPO_RE.match(value):
        return AssetType.REPOSITORY
    if value.lower() in KNOWN_CHAINS:
        return AssetType.CHAIN
    if "://" in value:
        return AssetType.API
    if DOMAIN_RE.match(value):
        return AssetType.DOMAIN
    return AssetType.OTHER


@dataclass
class ScopeDecision:
    status: AssetScope
    rule_id: int | None = None
    detail: str = ""


def _domain_matches(rule_value: str, host: str) -> bool:
    rule_value = rule_value.lower()
    if rule_value.startswith("*."):
        base = rule_value[2:]
        return host.endswith("." + base)
    return host == rule_value


def _rule_matches(rule, asset_type: AssetType, identifier: str, chain: str | None, in_scope_chains: set[str]) -> bool:
    rtype = AssetType(rule.rule_type) if rule.rule_type in AssetType._value2member_map_ else None
    if rtype is None:
        return False
    if asset_type == AssetType.CONTRACT:
        if rtype != AssetType.CONTRACT or rule.value.lower() != identifier.lower():
            return False
        rule_chain = normalize_chain(rule.chain)
        asset_chain = normalize_chain(chain)
        if rule_chain:
            return asset_chain is not None and asset_chain.lower() == rule_chain.lower()
        if asset_chain and in_scope_chains:
            return asset_chain.lower() in in_scope_chains
        return True
    if asset_type == AssetType.REPOSITORY:
        if rtype != AssetType.REPOSITORY:
            return False
        asset_repo = normalize_repo(identifier)
        rule_repo = normalize_repo(rule.value.replace("/*", "/__all__"))
        if not asset_repo or not rule_repo:
            return False
        if rule_repo.endswith("/__all__"):
            return asset_repo.startswith(rule_repo[: -len("__all__")])
        return asset_repo == rule_repo
    if asset_type == AssetType.CHAIN:
        return rtype == AssetType.CHAIN and (
            normalize_chain(rule.value) or ""
        ).lower() == (normalize_chain(identifier) or "").lower()
    if asset_type in (AssetType.API, AssetType.RPC, AssetType.DOMAIN, AssetType.DOCUMENTATION):
        host = normalize_domain(identifier)
        if rtype in (AssetType.API, AssetType.RPC) and "://" in rule.value:
            if "://" in identifier:
                return identifier.lower().rstrip("/").startswith(rule.value.lower().rstrip("/"))
            return False
        if rtype in (AssetType.DOMAIN, AssetType.API, AssetType.RPC):
            return _domain_matches(normalize_domain(rule.value) if not rule.value.startswith("*.") else rule.value, host)
        return False
    return rtype == asset_type and rule.value.strip().lower() == identifier.strip().lower()


def evaluate(
    rules: Iterable,
    identifier: str,
    asset_type: AssetType | str | None = None,
    chain: str | None = None,
    require_confirmed: bool = True,
) -> ScopeDecision:
    """Check one asset against a program's scope rules.

    Out-of-scope rules win over in-scope rules. When require_confirmed is
    true, only rules confirmed by the program (or by the user) count as
    in-scope; listed-but-unconfirmed rules still count for exclusion.
    """
    asset_type = AssetType(asset_type) if asset_type else guess_asset_type(identifier)
    rules = list(rules)
    usable_in = [r for r in rules if r.in_scope and (r.confirmed or not require_confirmed)]
    out = [r for r in rules if not r.in_scope]
    in_scope_chains = {
        (normalize_chain(r.value) or "").lower()
        for r in usable_in
        if r.rule_type == AssetType.CHAIN
    }
    for rule in out:
        if _rule_matches(rule, asset_type, identifier, chain, in_scope_chains):
            return ScopeDecision(AssetScope.OUT_OF_SCOPE, rule.id, f"excluded by rule {rule.value}")
    for rule in usable_in:
        if _rule_matches(rule, asset_type, identifier, chain, in_scope_chains):
            return ScopeDecision(AssetScope.IN_SCOPE, rule.id, f"matched rule {rule.value}")
    return ScopeDecision(AssetScope.SCOPE_UNKNOWN, None, "no explicit scope rule matches")


def parse_scope_document(doc: dict) -> list[dict]:
    """Turn the YAML scope format into rule dicts.

    scope:
      domains: [example.com]
      contracts: ["0x...", {address: "0x...", chain: Ethereum}]
      repositories: [github.com/example/project]
      chains: [Ethereum, Arbitrum]
      apis: [https://api.example.com]
      out_of_scope: [third_party_services, legacy.example.com]
    """
    scope = doc.get("scope", doc) or {}
    rules: list[dict] = []
    for d in scope.get("domains") or []:
        rules.append({"rule_type": AssetType.DOMAIN, "value": normalize_domain(d) if not str(d).startswith("*.") else str(d).lower(), "in_scope": True})
    for c in scope.get("contracts") or []:
        if isinstance(c, dict):
            rules.append({"rule_type": AssetType.CONTRACT, "value": c["address"].lower(), "chain": normalize_chain(c.get("chain")), "in_scope": True})
        else:
            rules.append({"rule_type": AssetType.CONTRACT, "value": str(c).lower(), "in_scope": True})
    for r in scope.get("repositories") or []:
        rules.append({"rule_type": AssetType.REPOSITORY, "value": normalize_repo(r) or r, "in_scope": True})
    for ch in scope.get("chains") or []:
        rules.append({"rule_type": AssetType.CHAIN, "value": normalize_chain(ch), "in_scope": True})
    for a in scope.get("apis") or []:
        rules.append({"rule_type": AssetType.API, "value": a, "in_scope": True})
    for item in scope.get("out_of_scope") or []:
        item = str(item)
        kind = guess_asset_type(item)
        if kind == AssetType.OTHER:
            rules.append({"rule_type": "category", "value": item.lower(), "in_scope": False})
        else:
            value = {
                AssetType.DOMAIN: lambda v: v.lower(),
                AssetType.REPOSITORY: lambda v: normalize_repo(v) or v,
                AssetType.CONTRACT: lambda v: v.lower(),
                AssetType.CHAIN: normalize_chain,
            }.get(kind, lambda v: v)(item)
            rules.append({"rule_type": kind, "value": value, "in_scope": False})
    return rules


def prohibited_methods_for(rules: Iterable) -> set[str]:
    methods: set[str] = set()
    for r in rules:
        if r.rule_type == "category" and not r.in_scope:
            methods.update(CATEGORY_METHODS.get(r.value.lower(), []))
    return methods


def add_rules(
    session: Session,
    program,
    rule_dicts: list[dict],
    source: str,
    confirmed: bool,
    evidence_response_id: int | None = None,
):
    """Insert scope rules, skipping exact duplicates. Confirming an existing
    listed rule upgrades it in place."""
    from ..models import ScopeRule

    existing = {
        (r.rule_type, r.value.lower(), (r.chain or "").lower(), r.in_scope): r
        for r in program.scope_rules
    }
    added = []
    for rd in rule_dicts:
        key = (str(rd["rule_type"]), str(rd["value"]).lower(), (rd.get("chain") or "").lower(), rd["in_scope"])
        if key in existing:
            rule = existing[key]
            if confirmed and not rule.confirmed:
                rule.confirmed = True
                rule.source = source
                rule.evidence_response_id = evidence_response_id
                added.append(rule)
            continue
        rule = ScopeRule(
            program_id=program.id,
            rule_type=str(rd["rule_type"]),
            value=str(rd["value"]),
            chain=rd.get("chain"),
            in_scope=rd["in_scope"],
            confirmed=confirmed,
            source=source,
            evidence_response_id=evidence_response_id,
        )
        session.add(rule)
        program.scope_rules.append(rule)
        existing[key] = rule
        added.append(rule)
    session.flush()
    if added:
        audit.record(
            session,
            AuditEventType.SCOPE_UPDATED,
            program.id,
            source=source,
            confirmed=confirmed,
            rules=[
                {"type": r.rule_type, "value": r.value, "chain": r.chain, "in_scope": r.in_scope}
                for r in added
            ],
        )
    return added


def has_confirmed_in_scope_assets(program) -> bool:
    return any(
        r.in_scope and r.confirmed and r.rule_type != AssetType.CHAIN for r in program.scope_rules
    )
