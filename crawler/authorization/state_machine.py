"""Authorization state machine.

Happy path:
  DISCOVERED -> PRIVATE_CANDIDATE -> AUTHORIZATION_REQUESTED -> AWAITING_RESPONSE
  -> AUTHORIZED -> SCOPE_CONFIRMED -> BOUNTY_CONFIRMED -> READY_FOR_RESEARCH

Only AUTHORIZED + SCOPE_CONFIRMED (+ BOUNTY_CONFIRMED when the user requires
bounty confirmation) may reach READY_FOR_RESEARCH. Every transition is
validated here and written to the audit log.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from .. import audit
from ..enums import AuditEventType, AuthState as S

_REVOKE = {S.NOT_AUTHORIZED, S.DECLINED, S.SCOPE_UNCLEAR, S.EXPIRED_AUTHORIZATION}

TRANSITIONS: dict[S, set[S]] = {
    S.DISCOVERED: {S.PRIVATE_CANDIDATE, S.AUTHORIZATION_REQUESTED, S.VDP_ONLY},
    S.PRIVATE_CANDIDATE: {S.AUTHORIZATION_REQUESTED, S.VDP_ONLY, S.DISCOVERED},
    S.AUTHORIZATION_REQUESTED: {S.AWAITING_RESPONSE, S.PRIVATE_CANDIDATE, S.DISCOVERED},
    S.AWAITING_RESPONSE: {
        S.AUTHORIZED,
        S.NOT_AUTHORIZED,
        S.DECLINED,
        S.NO_RESPONSE,
        S.VDP_ONLY,
        S.SCOPE_UNCLEAR,
    },
    S.AUTHORIZED: {S.SCOPE_CONFIRMED} | _REVOKE,
    S.SCOPE_UNCLEAR: {S.SCOPE_CONFIRMED, S.AWAITING_RESPONSE, S.AUTHORIZATION_REQUESTED} | _REVOKE,
    S.SCOPE_CONFIRMED: {S.BOUNTY_CONFIRMED, S.BOUNTY_NOT_AVAILABLE, S.READY_FOR_RESEARCH}
    | _REVOKE,
    S.BOUNTY_CONFIRMED: {S.READY_FOR_RESEARCH} | _REVOKE,
    S.BOUNTY_NOT_AVAILABLE: {S.READY_FOR_RESEARCH, S.BOUNTY_CONFIRMED} | _REVOKE,
    S.READY_FOR_RESEARCH: {S.BOUNTY_CONFIRMED, S.BOUNTY_NOT_AVAILABLE} | _REVOKE,
    S.NO_RESPONSE: {S.AUTHORIZATION_REQUESTED, S.AWAITING_RESPONSE, S.NOT_AUTHORIZED},
    S.NOT_AUTHORIZED: {S.AUTHORIZATION_REQUESTED},
    S.DECLINED: {S.AUTHORIZATION_REQUESTED},
    S.VDP_ONLY: {S.AUTHORIZATION_REQUESTED, S.PRIVATE_CANDIDATE},
    S.EXPIRED_AUTHORIZATION: {S.AUTHORIZATION_REQUESTED, S.AWAITING_RESPONSE},
}

# States in which the program holds a valid, scope-confirmed authorization.
AUTHORIZED_AND_SCOPED = frozenset(
    {S.SCOPE_CONFIRMED, S.BOUNTY_CONFIRMED, S.BOUNTY_NOT_AVAILABLE, S.READY_FOR_RESEARCH}
)
# States in which authorization has been granted (scope may still be pending).
AUTHORIZED_STATES = AUTHORIZED_AND_SCOPED | {S.AUTHORIZED}


class InvalidTransition(ValueError):
    pass


def can_transition(current: str, target: str) -> bool:
    return S(target) in TRANSITIONS.get(S(current), set())


def transition(session: Session, program, target: S, reason: str, actor: str = "system") -> None:
    current = S(program.authorization_status)
    target = S(target)
    if current == target:
        return
    if not can_transition(current, target):
        raise InvalidTransition(f"{program.name}: {current} -> {target} is not allowed")
    if target in (S.READY_FOR_RESEARCH,):
        _assert_ready(program)
    program.authorization_status = target
    audit.record(
        session,
        AuditEventType.AUTHORIZATION_STATE_CHANGED,
        program.id,
        from_state=current,
        to_state=target,
        reason=reason,
        actor=actor,
    )


def _assert_ready(program) -> None:
    from ..config import get_settings
    from ..enums import BountyStatus, ScopeStatus

    if program.authorized_at is None or not program.authorization_evidence:
        raise InvalidTransition("READY_FOR_RESEARCH requires recorded authorization evidence")
    if program.scope_status != ScopeStatus.CONFIRMED:
        raise InvalidTransition("READY_FOR_RESEARCH requires confirmed scope")
    if (
        get_settings().require_bounty_confirmation
        and program.bounty_status != BountyStatus.CONFIRMED
    ):
        raise InvalidTransition(
            "READY_FOR_RESEARCH requires bounty confirmation (REQUIRE_BOUNTY_CONFIRMATION=true)"
        )
