"""Discovery pipeline: Collectors -> Normalizer -> Classifier -> Private
filter -> (stored, ready for the Authorization Manager).

Discovery is passive. Nothing here contacts a target beyond reading the
public pages the collectors are configured for.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, notifications, scoring
from .authorization.state_machine import transition
from .classifier import classify
from .collectors import REGISTRY, Collector
from .config import PlatformConfig, Settings, get_settings
from .enums import AuditEventType, AuthState, BountyStatus, Classification, ScopeStatus
from .filters import PRIVATE_CLASSES
from .models import Platform, Program, utcnow
from .normalizer import NormalizedProgram, normalize
from .scope import engine as scope_engine

log = logging.getLogger("crawler.pipeline")


@dataclass
class DiscoveryResult:
    by_collector: dict[str, int] = field(default_factory=dict)
    new: list[int] = field(default_factory=list)
    updated: list[int] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def sync_platforms(session: Session, pc: PlatformConfig) -> dict[str, Platform]:
    existing = {p.slug: p for p in session.scalars(select(Platform))}
    for slug, info in pc.platforms.items():
        p = existing.get(slug) or Platform(slug=slug, name=info.get("name") or slug)
        p.name = info.get("name") or slug
        p.url = info.get("url")
        p.has_reputation_system = bool(info.get("has_reputation_system"))
        for key in PlatformConfig.ACCESS_KEYS:
            setattr(p, key, bool(info.get(key)))
        session.add(p)
        existing[slug] = p
    session.flush()
    return existing


def _platform(session: Session, platforms: dict[str, Platform], slug: str) -> Platform:
    if slug not in platforms:
        p = Platform(slug=slug, name=slug.title())
        session.add(p)
        session.flush()
        platforms[slug] = p
    return platforms[slug]


def upsert_program(
    session: Session, np: NormalizedProgram, pc: PlatformConfig, platforms: dict[str, Platform]
) -> tuple[Program, bool]:
    program = session.scalars(select(Program).where(Program.dedupe_key == np.dedupe_key)).first()
    created = program is None
    if created:
        program = Program(dedupe_key=np.dedupe_key, name=np.name, platform=_platform(session, platforms, np.platform))
        session.add(program)
    defaults = pc.defaults_for(np.platform)
    program.name = np.name
    program.project_name = np.project_name
    program.protocol_name = np.protocol_name
    program.program_url = np.program_url
    program.source_url = np.source_url
    program.collector = np.collector
    program.program_type = np.program_type
    for key in PlatformConfig.ACCESS_KEYS:
        value = getattr(np, key)
        setattr(program, key, defaults[key] if value is None else bool(value))
    program.listed_scope = np.listed_scope
    program.listed_out_of_scope = np.listed_out_of_scope
    program.max_severity = np.max_severity
    program.max_bounty = np.max_bounty
    program.bounty_currency = np.bounty_currency
    program.payment_info = np.payment_info
    program.safe_harbor = np.safe_harbor
    program.disclosure_policy = np.disclosure_policy
    program.program_status = np.program_status
    program.source_last_updated = np.last_updated
    program.security_email = np.security_email or program.security_email
    program.notes = np.notes
    # YAML seeds can carry dates; keep raw JSON-safe.
    program.raw = json.loads(json.dumps({k: v for k, v in np.raw.items() if k != "description"}, default=str))
    program.last_seen_at = utcnow()
    if program.bounty_status in (None, BountyStatus.UNKNOWN) and np.max_bounty:
        program.bounty_status = BountyStatus.LISTED
    session.flush()
    return program, created


def _record_listed_scope(session: Session, program: Program, np: NormalizedProgram) -> None:
    rules = [
        {"rule_type": s["type"], "value": s["value"], "chain": s.get("chain"), "in_scope": True}
        for s in np.listed_scope
        if s["type"] in {t.value for t in scope_engine.AssetType}
    ]
    doc_out = scope_engine.parse_scope_document({"out_of_scope": np.listed_out_of_scope})
    scope_engine.add_rules(session, program, rules + doc_out, source="program_listing", confirmed=False)
    if program.scope_status in (None, ScopeStatus.UNKNOWN) and rules:
        program.scope_status = ScopeStatus.LISTED


def discover(
    session: Session,
    collectors: list[Collector] | None = None,
    settings: Settings | None = None,
    extra_exclusions: list[str] | None = None,
    progress=None,
) -> DiscoveryResult:
    settings = settings or get_settings()
    pc = PlatformConfig(settings.load_yaml("platforms.yaml"), settings.platform_exclusion_list + list(extra_exclusions or []))
    platforms = sync_platforms(session, pc)
    collectors = collectors if collectors is not None else [cls(settings) for cls in REGISTRY.values()]
    result = DiscoveryResult()
    scoring_cfg = settings.load_yaml("scoring.yaml")

    for collector in collectors:
        if not collector.enabled():
            continue
        if progress:
            progress(f"Reading {collector.name}...")
        try:
            raws = list(collector.collect())
        except Exception as exc:  # noqa: BLE001
            log.exception("collector %s failed", collector.name)
            result.errors.append(f"{collector.name}: {exc}")
            continue
        result.by_collector[collector.name] = len(raws)
        for raw in raws:
            try:
                np = normalize(raw, collector.name)
            except ValueError as exc:
                result.errors.append(f"{collector.name}: {exc}")
                continue
            if np.platform in pc.excluded_platforms:
                result.skipped.append(f"{np.name} ({np.platform} excluded)")
                continue
            program, created = upsert_program(session, np, pc, platforms)
            _record_listed_scope(session, program, np)
            classification, reasons = classify(np)
            changed = classification != program.classification
            program.classification = classification
            program.classification_reasons = reasons
            if created:
                audit.record(
                    session,
                    AuditEventType.PROGRAM_DISCOVERED,
                    program.id,
                    name=program.name,
                    platform=np.platform,
                    source_url=program.source_url,
                    collector=collector.name,
                )
                result.new.append(program.id)
            else:
                result.updated.append(program.id)
            if created or changed:
                audit.record(
                    session,
                    AuditEventType.PROGRAM_CLASSIFIED,
                    program.id,
                    classification=classification,
                    reasons=reasons,
                )
            if classification == Classification.VDP_ONLY and program.authorization_status in (
                AuthState.DISCOVERED,
                AuthState.PRIVATE_CANDIDATE,
            ):
                transition(session, program, AuthState.VDP_ONLY, "classified as VDP only")
            if classification in PRIVATE_CLASSES and program.authorization_status == AuthState.DISCOVERED:
                transition(session, program, AuthState.PRIVATE_CANDIDATE, f"classified {classification}")
                notifications.notify(
                    session,
                    notifications.PRIVATE_PROGRAM_DISCOVERED,
                    f"Private program candidate: {program.name} ({classification}). "
                    "Generate an authorization request before any testing.",
                    program.id,
                )
            program.opportunity_score = scoring.score(program, cfg=scoring_cfg)
    session.flush()
    return result
