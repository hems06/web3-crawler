"""Report rendering and API serialisation."""

from __future__ import annotations

import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit, status
from .enums import AuditEventType
from .models import AuditEvent, Program, utcnow


def program_dict(p: Program) -> dict:
    icon, label = status.indicator(p)
    return {
        "id": p.id,
        "name": p.name,
        "project_name": p.project_name,
        "protocol_name": p.protocol_name,
        "platform": p.platform.slug if p.platform else None,
        "program_url": p.program_url,
        "source_url": p.source_url,
        "program_type": p.classification,
        "source_program_type": p.program_type,
        "classification_reasons": p.classification_reasons,
        "authorization_status": p.authorization_status,
        "bounty_status": p.bounty_status,
        "scope_status": p.scope_status,
        "max_bounty": p.max_bounty,
        "bounty_currency": p.bounty_currency,
        "max_severity": p.max_severity,
        "payment_info": p.payment_info,
        "safe_harbor": p.safe_harbor,
        "disclosure_policy": p.disclosure_policy,
        "program_status": p.program_status,
        "security_email": p.security_email,
        "platform_reputation_required": p.platform_reputation_required,
        "invite_required": p.invite_required,
        "application_required": p.application_required,
        "private_program_supported": p.private_program_supported,
        "opportunity_score": p.opportunity_score,
        "authorized_at": p.authorized_at,
        "authorization_expires_at": p.authorization_expires_at,
        "authorization_evidence": p.authorization_evidence,
        "testing_restrictions": p.testing_restrictions,
        "last_updated": p.source_last_updated,
        "last_verified": p.last_verified,
        "discovered_at": p.discovered_at,
        "indicator": {"icon": icon, "label": label},
        "workflow_status": status.workflow_status(p),
    }


def render(session: Session, fmt: str = "md") -> str:
    programs = session.scalars(select(Program).order_by(Program.opportunity_score.desc())).all()
    by_state: dict[str, int] = {}
    for p in programs:
        by_state[p.authorization_status] = by_state.get(p.authorization_status, 0) + 1
    blocked = session.scalar(
        select(func.count()).select_from(AuditEvent).where(AuditEvent.event_type == AuditEventType.RESEARCH_BLOCKED)
    )
    chain_ok, bad = audit.verify_chain(session)
    if fmt == "json":
        return json.dumps(
            {
                "generated_at": utcnow().isoformat(),
                "programs": [program_dict(p) for p in programs],
                "authorization_states": by_state,
                "blocked_actions": blocked,
                "audit_chain_intact": chain_ok,
            },
            indent=2,
            default=str,
        )
    lines = [
        "# Web3 crawler report",
        "",
        f"Generated {utcnow():%Y-%m-%d %H:%M UTC}. {len(programs)} programs, {blocked} blocked research actions. "
        f"Audit chain {'intact' if chain_ok else f'BROKEN at event #{bad}'}.",
        "",
        "## Authorization states",
        "",
    ]
    lines += [f"- {k}: {v}" for k, v in sorted(by_state.items())]
    lines += ["", "## Programs", "", "| Program | Platform | Type | Authorization | Bounty | Scope | Score |", "|---|---|---|---|---|---|---|"]
    for p in programs:
        icon, label = status.indicator(p)
        lines.append(
            f"| {p.name} | {p.platform.slug} | {p.classification} | {icon} {p.authorization_status} | "
            f"{p.bounty_status} | {p.scope_status} | {p.opportunity_score} |"
        )
    return "\n".join(lines) + "\n"
