"""Asset intelligence: build the asset inventory for a program and enrich it
from public, passive sources. Every asset is checked against the scope
engine; anything that does not match confirmed scope is SCOPE_UNKNOWN."""

from __future__ import annotations

import logging

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..authorization.state_machine import AUTHORIZED_STATES
from ..config import Settings, get_settings
from ..enums import AssetScope, AssetType, AuditEventType
from ..models import Asset, Contract, Program, utcnow
from ..scope import engine as scope_engine
from . import contracts as contract_meta

log = logging.getLogger("crawler.assets")


class NotAuthorizedForIntel(PermissionError):
    pass


def upsert_asset(
    session: Session, program: Program, asset_type: str, identifier: str, chain: str | None, source: str,
    details: dict | None = None, settings: Settings | None = None,
) -> Asset:
    settings = settings or get_settings()
    chain = scope_engine.normalize_chain(chain)
    asset = session.scalars(
        select(Asset).where(
            Asset.program_id == program.id,
            Asset.asset_type == str(asset_type),
            Asset.identifier == identifier,
            Asset.chain.is_(None) if chain is None else Asset.chain == chain,
        )
    ).first()
    decision = scope_engine.evaluate(
        program.scope_rules, identifier, asset_type=asset_type, chain=chain, require_confirmed=settings.require_explicit_scope
    )
    if asset is None:
        asset = Asset(program_id=program.id, asset_type=str(asset_type), identifier=identifier, chain=chain, source=source, details=details or {})
        asset.scope_status = decision.status
        session.add(asset)
        session.flush()
        audit.record(
            session, AuditEventType.ASSET_DISCOVERED, program.id,
            asset=identifier, asset_type=str(asset_type), chain=chain, source=source, scope=decision.status,
        )
    else:
        asset.scope_status = decision.status
        if details:
            asset.details = {**(asset.details or {}), **details}
    return asset


def sync_from_scope(session: Session, program: Program, settings: Settings | None = None) -> list[Asset]:
    """Create assets for every scope rule and publicly listed scope item.
    This only copies what is already known; it contacts nothing."""
    out = []
    for rule in program.scope_rules:
        if rule.rule_type == "category" or rule.rule_type not in AssetType._value2member_map_:
            continue
        out.append(upsert_asset(session, program, rule.rule_type, rule.value, rule.chain, f"scope:{rule.source}", settings=settings))
    for item in program.listed_scope or []:
        if item.get("type") in AssetType._value2member_map_:
            out.append(upsert_asset(session, program, item["type"], item["value"], item.get("chain"), "program_listing", settings=settings))
    session.flush()
    return out


def _authorized(program: Program) -> bool:
    return program.authorized_at is not None and program.authorization_status in AUTHORIZED_STATES


def enrich_contracts(session: Session, program: Program, settings: Settings | None = None, client: httpx.Client | None = None) -> list[Contract]:
    """Read public verification metadata for in-scope contracts of an
    authorized program."""
    settings = settings or get_settings()
    if not _authorized(program):
        raise NotAuthorizedForIntel(f"{program.name} is not authorized; asset intelligence is blocked")
    client = client or httpx.Client(timeout=20, headers={"User-Agent": settings.crawler_user_agent})
    results = []
    for asset in session.scalars(
        select(Asset).where(Asset.program_id == program.id, Asset.asset_type == AssetType.CONTRACT, Asset.scope_status == AssetScope.IN_SCOPE)
    ):
        chain = asset.chain or "Ethereum"
        meta = None
        try:
            meta = contract_meta.from_etherscan(asset.identifier, chain, settings.etherscan_api_key, client)
            if meta is None:
                meta = contract_meta.from_sourcify(asset.identifier, chain, client)
        except httpx.HTTPError as exc:
            log.warning("contract metadata lookup failed for %s: %s", asset.identifier, exc)
        contract = session.scalars(
            select(Contract).where(Contract.program_id == program.id, Contract.address == asset.identifier, Contract.chain == chain)
        ).first() or Contract(program_id=program.id, asset_id=asset.id, address=asset.identifier, chain=chain)
        for key, value in (meta or {}).items():
            setattr(contract, key, value)
        contract.fetched_at = utcnow()
        session.add(contract)
        results.append(contract)
        if contract.implementation_address:
            # The implementation is a separate asset. It is in scope only if
            # the program's confirmed scope says so.
            upsert_asset(session, program, AssetType.CONTRACT, contract.implementation_address.lower(), chain, f"proxy-of:{asset.identifier}", settings=settings)
    session.flush()
    return results


def certificate_transparency_subdomains(domain: str, client: httpx.Client) -> list[str]:
    """Passive subdomain listing from public certificate transparency logs."""
    resp = client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
    resp.raise_for_status()
    names = set()
    for row in resp.json():
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith("." + domain) or name == domain:
                names.add(name)
    return sorted(names)


def discover_passive(session: Session, program: Program, settings: Settings | None = None, client: httpx.Client | None = None) -> list[Asset]:
    """Passive discovery for an authorized program: CT-log subdomains for
    confirmed in-scope domains, plus contract metadata. New assets land as
    SCOPE_UNKNOWN unless confirmed scope covers them."""
    settings = settings or get_settings()
    if not _authorized(program):
        raise NotAuthorizedForIntel(f"{program.name} is not authorized; asset intelligence is blocked")
    client = client or httpx.Client(timeout=30, headers={"User-Agent": settings.crawler_user_agent})
    found = sync_from_scope(session, program, settings)
    for rule in program.scope_rules:
        if rule.rule_type == AssetType.DOMAIN and rule.in_scope and rule.confirmed:
            base = rule.value[2:] if rule.value.startswith("*.") else rule.value
            try:
                for sub in certificate_transparency_subdomains(base, client):
                    found.append(upsert_asset(session, program, AssetType.DOMAIN, sub, None, "certificate_transparency", settings=settings))
            except (httpx.HTTPError, ValueError) as exc:
                log.warning("CT lookup failed for %s: %s", base, exc)
    enrich_contracts(session, program, settings, client)
    return found
