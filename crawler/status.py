"""Human-facing status labels shared by the CLI, API and dashboard."""

from __future__ import annotations

from .enums import AuthState as S, BountyStatus
from .models import as_utc, utcnow

NOT_AUTHORIZED = ("🔴", "NOT AUTHORIZED")
WAITING = ("🟡", "WAITING FOR RESPONSE")
SCOPE_UNCLEAR = ("🟠", "SCOPE UNCLEAR")
AUTHORIZED = ("🟢", "AUTHORIZED")
BOUNTY_CONFIRMED = ("🔵", "BOUNTY CONFIRMED")


def indicator(program) -> tuple[str, str]:
    state = S(program.authorization_status)
    if state in (S.AUTHORIZATION_REQUESTED, S.AWAITING_RESPONSE):
        return WAITING
    if state in (S.AUTHORIZED, S.SCOPE_UNCLEAR):
        return SCOPE_UNCLEAR
    if state in (S.SCOPE_CONFIRMED, S.BOUNTY_NOT_AVAILABLE, S.BOUNTY_CONFIRMED, S.READY_FOR_RESEARCH):
        exp = as_utc(program.authorization_expires_at)
        if exp is not None and exp <= utcnow():
            return NOT_AUTHORIZED
        return BOUNTY_CONFIRMED if program.bounty_status == BountyStatus.CONFIRMED else AUTHORIZED
    return NOT_AUTHORIZED


def workflow_status(program) -> str:
    state = S(program.authorization_status)
    return {
        S.DISCOVERED: "WAITING_FOR_AUTHORIZATION",
        S.PRIVATE_CANDIDATE: "WAITING_FOR_AUTHORIZATION",
        S.AUTHORIZATION_REQUESTED: "EMAIL_DRAFTED",
        S.AWAITING_RESPONSE: "AWAITING_RESPONSE",
    }.get(state, state.value)


def authorization_label(program) -> str:
    if program.authorized_at is None:
        return "REQUIRED"
    exp = as_utc(program.authorization_expires_at)
    if exp is not None and exp <= utcnow():
        return "EXPIRED"
    return f"GRANTED (until {exp.date().isoformat()})" if exp else "GRANTED"
