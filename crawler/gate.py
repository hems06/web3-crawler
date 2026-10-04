"""Hard authorization gate.

Every research action must call check_authorization() and must not proceed
unless the decision is allowed. The gate reads RESEARCH_MODE from the process
environment only; nothing in the API or dashboard can change it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .authorization.state_machine import AUTHORIZED_AND_SCOPED, AUTHORIZED_STATES
from .config import Settings, get_settings
from .enums import (
    DEFAULT_PERMITTED_METHODS,
    FORBIDDEN_METHODS,
    AssetScope,
    AuditEventType,
    BountyStatus,
    ResearchMethod,
    ScopeStatus,
)
from .models import Program, ResearchSession, ScopeRule, as_utc, utcnow
from .scope import engine as scope_engine


class AuthorizationBlocked(PermissionError):
    def __init__(self, decision: "GateDecision"):
        super().__init__(f"BLOCKED {decision.asset}: {', '.join(decision.reasons)}")
        self.decision = decision


@dataclass
class GateDecision:
    asset: str
    method: str
    allowed: bool
    program_id: int | None
    reasons: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=utcnow)

    @property
    def reason(self) -> str | None:
        return self.reasons[0] if self.reasons else None

    def as_event(self) -> dict:
        """The AuthorizationBlockedEvent shape."""
        return {
            "asset": self.asset,
            "reason": self.reason,
            "reasons": self.reasons,
            "method": self.method,
            "program_id": self.program_id,
            "timestamp": self.timestamp.isoformat(),
            "action": "ALLOWED" if self.allowed else "BLOCKED",
        }


def _resolve_program(session: Session, asset: str, chain: str | None, program_id: int | None):
    if program_id is not None:
        return session.get(Program, program_id)
    # Find the single program whose confirmed in-scope rules match the asset.
    matches = []
    for program in session.scalars(select(Program).join(ScopeRule).distinct()):
        decision = scope_engine.evaluate(program.scope_rules, asset, chain=chain)
        if decision.status == AssetScope.IN_SCOPE:
            matches.append(program)
    return matches[0] if len(matches) == 1 else None


def check_authorization(
    session: Session,
    asset: str,
    method: ResearchMethod | str,
    program_id: int | None = None,
    chain: str | None = None,
    asset_type: str | None = None,
    settings: Settings | None = None,
    record_session: bool = True,
) -> GateDecision:
    """Evaluate all six gate conditions. Blocked decisions are always logged.

    1. program exists          4. asset is inside confirmed scope
    2. authorization is valid  5. testing method is permitted
    3. not expired             6. RESEARCH_MODE is enabled
    """
    settings = settings or get_settings()
    reasons: list[str] = []
    try:
        method = ResearchMethod(method)
    except ValueError:
        reasons.append("UNKNOWN_METHOD")
    program = _resolve_program(session, asset, chain, program_id)

    if program is None:
        reasons.append("PROGRAM_NOT_FOUND" if program_id is not None else "SCOPE_UNKNOWN")
    else:
        state = program.authorization_status
        if state not in AUTHORIZED_STATES or not program.authorized_at or not program.authorization_evidence:
            reasons.append("NOT_AUTHORIZED")
        expires = as_utc(program.authorization_expires_at)
        if state == "EXPIRED_AUTHORIZATION" or (expires is not None and expires <= utcnow()):
            reasons.append("AUTHORIZATION_EXPIRED")
        if state not in AUTHORIZED_AND_SCOPED or program.scope_status != ScopeStatus.CONFIRMED:
            reasons.append("SCOPE_NOT_CONFIRMED")
        if settings.require_bounty_confirmation and program.bounty_status != BountyStatus.CONFIRMED:
            reasons.append("BOUNTY_NOT_CONFIRMED")
        decision = scope_engine.evaluate(
            program.scope_rules,
            asset,
            asset_type=asset_type,
            chain=chain,
            require_confirmed=True if settings.require_explicit_scope else False,
        )
        if decision.status != AssetScope.IN_SCOPE:
            reasons.append(decision.status.value)
        if isinstance(method, ResearchMethod):
            prohibited = set(program.prohibited_methods or []) | scope_engine.prohibited_methods_for(
                program.scope_rules
            )
            permitted = set(program.permitted_methods or []) | {m.value for m in DEFAULT_PERMITTED_METHODS}
            if method in FORBIDDEN_METHODS or method.value in prohibited:
                reasons.append("METHOD_PROHIBITED")
            elif method.value not in permitted:
                reasons.append("METHOD_NOT_PERMITTED")

    if isinstance(method, ResearchMethod) and method in FORBIDDEN_METHODS and "METHOD_PROHIBITED" not in reasons:
        reasons.append("METHOD_PROHIBITED")
    if not settings.research_mode:
        reasons.append("RESEARCH_MODE_DISABLED")

    result = GateDecision(
        asset=asset,
        method=str(method.value if isinstance(method, ResearchMethod) else method),
        allowed=not reasons,
        program_id=program.id if program else None,
        reasons=reasons,
    )
    if not result.allowed:
        audit.record(
            session,
            AuditEventType.RESEARCH_BLOCKED,
            result.program_id,
            event="AuthorizationBlockedEvent",
            **{k: v for k, v in result.as_event().items() if k != "program_id"},
        )
        if record_session:
            session.add(
                ResearchSession(
                    program_id=result.program_id,
                    asset=asset,
                    method=result.method,
                    status="BLOCKED",
                    reasons=reasons,
                )
            )
            session.flush()
    return result


def require_authorization(session: Session, asset: str, method, **kwargs) -> GateDecision:
    """check_authorization() that raises AuthorizationBlocked on any failure."""
    decision = check_authorization(session, asset, method, **kwargs)
    if not decision.allowed:
        # Persist the blocked event before raising so a caller's rollback
        # cannot erase it from the audit log.
        session.commit()
        raise AuthorizationBlocked(decision)
    return decision
