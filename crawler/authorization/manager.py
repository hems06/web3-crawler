"""Authorization Manager: drafts requests, records replies, and moves
programs through the state machine. Nothing here performs testing."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, notifications, scoring
from ..config import Settings, get_settings
from ..enums import (
    AssetType,
    AuditEventType,
    AuthState as S,
    BountyStatus,
    RequestStatus,
    ResponseClass as R,
    ScopeStatus,
)
from ..models import AuthorizationRequest, AuthorizationResponse, BountyTerms, Program, as_utc, utcnow
from ..scope import engine as scope_engine
from . import email_generator, email_provider
from .response_parser import ParsedResponse, parse_response
from .state_machine import AUTHORIZED_STATES, can_transition, transition


class AuthorizationError(RuntimeError):
    pass


REQUESTABLE = {
    S.DISCOVERED,
    S.PRIVATE_CANDIDATE,
    S.NOT_AUTHORIZED,
    S.DECLINED,
    S.VDP_ONLY,
    S.NO_RESPONSE,
    S.EXPIRED_AUTHORIZATION,
    S.SCOPE_UNCLEAR,
}


# --------------------------------------------------------------------------
# Requests
# --------------------------------------------------------------------------

def generate_request(
    session: Session, program: Program, recipient: str | None = None, settings: Settings | None = None
) -> AuthorizationRequest:
    settings = settings or get_settings()
    subject, body = email_generator.generate(program, settings.researcher_name, settings.researcher_contact)
    req = AuthorizationRequest(
        program_id=program.id,
        recipient=recipient or program.security_email,
        subject=subject,
        body=body,
        status=RequestStatus.DRAFT,
    )
    session.add(req)
    session.flush()
    if S(program.authorization_status) in REQUESTABLE:
        transition(session, program, S.AUTHORIZATION_REQUESTED, f"authorization email #{req.id} drafted")
    audit.record(
        session,
        AuditEventType.AUTHORIZATION_EMAIL_GENERATED,
        program.id,
        request_id=req.id,
        recipient=req.recipient,
        subject=subject,
    )
    notifications.notify(
        session,
        notifications.AUTHORIZATION_EMAIL_READY,
        f"Authorization email for {program.name} is ready for review (request #{req.id})."
        + ("" if req.recipient else " No public security contact was found; add a recipient."),
        program.id,
    )
    return req


def approve_request(session: Session, req: AuthorizationRequest, actor: str = "user") -> None:
    if req.status != RequestStatus.DRAFT:
        raise AuthorizationError(f"request #{req.id} is {req.status}, not DRAFT")
    if not req.recipient:
        raise AuthorizationError(f"request #{req.id} has no recipient")
    req.status = RequestStatus.APPROVED
    req.approved_at = utcnow()
    audit.record(session, AuditEventType.AUTHORIZATION_EMAIL_APPROVED, req.program_id, request_id=req.id, actor=actor)


def _after_sent(session: Session, req: AuthorizationRequest, via: str) -> None:
    req.status = RequestStatus.SENT
    req.sent_at = utcnow()
    req.sent_via = via
    program = session.get(Program, req.program_id)
    if S(program.authorization_status) in REQUESTABLE:
        transition(session, program, S.AUTHORIZATION_REQUESTED, f"request #{req.id} sent")
    if can_transition(program.authorization_status, S.AWAITING_RESPONSE):
        transition(session, program, S.AWAITING_RESPONSE, f"request #{req.id} sent via {via}")
    audit.record(
        session,
        AuditEventType.AUTHORIZATION_EMAIL_SENT,
        req.program_id,
        request_id=req.id,
        recipient=req.recipient,
        via=via,
    )


def auto_send_blockers(session: Session, req: AuthorizationRequest, settings: Settings | None = None) -> list[str]:
    """Reasons this request may NOT go out under the standing approval.

    An empty list means it can be sent without asking. Otherwise the user is
    asked as usual.
    """
    settings = settings or get_settings()
    program = session.get(Program, req.program_id)
    reasons = []
    if not req.recipient or not program.security_email or req.recipient.strip().lower() != program.security_email.strip().lower():
        reasons.append("recipient is not the program's published security contact")
    already = session.scalars(
        select(AuthorizationRequest).where(
            AuthorizationRequest.program_id == req.program_id,
            AuthorizationRequest.status == RequestStatus.SENT,
            AuthorizationRequest.id != req.id,
        )
    ).first()
    if already is not None:
        reasons.append(f"request #{already.id} was already sent to this program")
    hour_ago = utcnow() - timedelta(hours=1)
    recent = [
        r for r in session.scalars(select(AuthorizationRequest).where(AuthorizationRequest.sent_at.is_not(None)))
        if as_utc(r.sent_at) >= hour_ago
    ]
    if len(recent) >= settings.auto_send_max_per_hour:
        reasons.append(f"rate limit: {len(recent)} emails sent in the last hour (AUTO_SEND_MAX_PER_HOUR={settings.auto_send_max_per_hour})")
    return reasons


def send_request(session: Session, req: AuthorizationRequest, settings: Settings | None = None, sender=None) -> None:
    """Send an APPROVED request through the configured provider."""
    settings = settings or get_settings()
    if req.status != RequestStatus.APPROVED:
        raise AuthorizationError(f"request #{req.id} must be approved before sending (status {req.status})")
    (sender or email_provider.send_email)(req.recipient, req.subject, req.body, settings)
    _after_sent(session, req, "smtp")


def mark_sent_manually(session: Session, req: AuthorizationRequest) -> None:
    """The user sent the draft from their own mail client."""
    if req.status not in (RequestStatus.DRAFT, RequestStatus.APPROVED):
        raise AuthorizationError(f"request #{req.id} is {req.status}")
    _after_sent(session, req, "manual")


# --------------------------------------------------------------------------
# Responses
# --------------------------------------------------------------------------

def record_response(
    session: Session,
    program: Program,
    body: str,
    sender: str | None = None,
    subject: str | None = None,
    request_id: int | None = None,
) -> AuthorizationResponse:
    """Store and parse a reply. It is NOT applied until a person reviews it."""
    parsed = parse_response(body, subject)
    if request_id is None:
        last = session.scalars(
            select(AuthorizationRequest)
            .where(AuthorizationRequest.program_id == program.id)
            .order_by(AuthorizationRequest.id.desc())
        ).first()
        request_id = last.id if last else None
    resp = AuthorizationResponse(
        program_id=program.id,
        request_id=request_id,
        sender=sender,
        subject=subject,
        body=body,
        classifications=parsed.classifications,
        extracted=parsed.to_dict(),
        evidence=parsed.evidence,
    )
    session.add(resp)
    session.flush()
    audit.record(
        session,
        AuditEventType.AUTHORIZATION_RESPONSE_RECEIVED,
        program.id,
        response_id=resp.id,
        sender=sender,
        classifications=parsed.classifications,
    )
    notifications.notify(
        session,
        notifications.RESPONSE_RECEIVED,
        f"Response from {sender or 'unknown sender'} for {program.name}: "
        f"{', '.join(parsed.classifications)}. Review it with `crawler verify apply {resp.id}`.",
        program.id,
    )
    return resp


def _ensure_awaiting(session: Session, program: Program, reason: str) -> None:
    state = S(program.authorization_status)
    if state in (S.DISCOVERED, S.PRIVATE_CANDIDATE, S.NOT_AUTHORIZED, S.DECLINED, S.VDP_ONLY, S.NO_RESPONSE):
        transition(session, program, S.AUTHORIZATION_REQUESTED, reason)
        state = S.AUTHORIZATION_REQUESTED
    if state in (S.AUTHORIZATION_REQUESTED, S.NO_RESPONSE, S.EXPIRED_AUTHORIZATION):
        transition(session, program, S.AWAITING_RESPONSE, reason)


def _revoke(session: Session, program: Program, target: S, reason: str) -> None:
    if S(program.authorization_status) in (S.AUTHORIZATION_REQUESTED,):
        transition(session, program, S.AWAITING_RESPONSE, reason)
    if can_transition(program.authorization_status, target):
        transition(session, program, target, reason)
    program.authorized_at = None
    program.authorization_expires_at = None
    program.authorization_evidence = None


def _grant(session: Session, program: Program, evidence: str, expires: datetime | None, settings: Settings, reason: str) -> None:
    state = S(program.authorization_status)
    if state not in AUTHORIZED_STATES and state != S.SCOPE_UNCLEAR:
        _ensure_awaiting(session, program, reason)
        transition(session, program, S.AUTHORIZED, reason)
    elif state == S.SCOPE_UNCLEAR and program.authorized_at is None:
        # Scope was unclear before authorization was ever granted; ask again.
        transition(session, program, S.AWAITING_RESPONSE, reason)
        transition(session, program, S.AUTHORIZED, reason)
    program.authorized_at = utcnow()
    program.authorization_expires_at = expires or utcnow() + timedelta(days=settings.authorization_expiry)
    program.authorization_evidence = evidence
    notifications.notify(
        session,
        notifications.AUTHORIZATION_CONFIRMED,
        f"Authorization recorded for {program.name}, valid until "
        f"{program.authorization_expires_at.date().isoformat()}.",
        program.id,
    )


def _scope_rules_from(parsed: ParsedResponse) -> list[dict]:
    chain = parsed.chains[0] if len(parsed.chains) == 1 else None
    rules: list[dict] = []
    rules += [{"rule_type": AssetType.DOMAIN, "value": d, "in_scope": True} for d in parsed.domains]
    rules += [{"rule_type": AssetType.CONTRACT, "value": c, "chain": chain, "in_scope": True} for c in parsed.contracts]
    rules += [{"rule_type": AssetType.REPOSITORY, "value": r, "in_scope": True} for r in parsed.repositories]
    rules += [{"rule_type": AssetType.API, "value": a, "in_scope": True} for a in parsed.apis]
    rules += [{"rule_type": AssetType.CHAIN, "value": c, "in_scope": True} for c in parsed.chains]
    rules += scope_engine.parse_scope_document({"out_of_scope": parsed.out_of_scope})
    return rules


def apply_response(
    session: Session, resp: AuthorizationResponse, settings: Settings | None = None, actor: str = "user"
) -> list[str]:
    """Apply a reviewed response to the program. Returns a list of changes."""
    settings = settings or get_settings()
    if resp.applied_at is not None:
        raise AuthorizationError(f"response #{resp.id} was already applied")
    program = session.get(Program, resp.program_id)
    parsed = ParsedResponse(**resp.extracted)
    changes: list[str] = []
    reason = f"response #{resp.id}"

    if parsed.has(R.NOT_AUTHORIZED):
        target = S.DECLINED if parsed.declined else S.NOT_AUTHORIZED
        _revoke(session, program, target, reason)
        changes.append(target.value)
    elif parsed.has(R.PARTIALLY_AUTHORIZED):
        _ensure_awaiting(session, program, reason)
        changes.append("partial authorization: follow-up needed, nothing unlocked")
    elif parsed.has(R.AUTHORIZED):
        expires = None
        if parsed.expiration:
            expires = datetime.fromisoformat(parsed.expiration).replace(tzinfo=timezone.utc)
        evidence = f"response #{resp.id} from {resp.sender or 'unknown'}: " + " | ".join(parsed.evidence[:5])
        _grant(session, program, evidence, expires, settings, reason)
        changes.append("AUTHORIZED")
    else:
        changes.append("no authorization decision in this response")

    authorized = program.authorized_at is not None and S(program.authorization_status) in (AUTHORIZED_STATES | {S.SCOPE_UNCLEAR})
    if authorized and parsed.has(R.SCOPE_CONFIRMED):
        scope_engine.add_rules(session, program, _scope_rules_from(parsed), "authorization_response", True, resp.id)
        if scope_engine.has_confirmed_in_scope_assets(program):
            program.scope_status = ScopeStatus.CONFIRMED
            notifications.notify(session, notifications.SCOPE_CHANGED, f"Scope confirmed for {program.name}.", program.id)
            changes.append("SCOPE_CONFIRMED")
    elif authorized and parsed.has(R.SCOPE_REQUIRES_CLARIFICATION):
        program.scope_status = ScopeStatus.UNCLEAR
        if can_transition(program.authorization_status, S.SCOPE_UNCLEAR):
            transition(session, program, S.SCOPE_UNCLEAR, reason)
        changes.append("SCOPE_UNCLEAR")

    if parsed.restrictions or parsed.prohibited_methods:
        program.testing_restrictions = sorted(set(program.testing_restrictions or []) | set(parsed.restrictions))
        program.prohibited_methods = sorted(set(program.prohibited_methods or []) | set(parsed.prohibited_methods))

    if parsed.has(R.BOUNTY_CONFIRMED) or parsed.has(R.BOUNTY_NOT_AVAILABLE):
        available = parsed.has(R.BOUNTY_CONFIRMED)
        session.add(
            BountyTerms(
                program_id=program.id,
                available=available,
                max_bounty=parsed.max_bounty,
                currency=parsed.bounty_currency,
                amounts=parsed.bounty_amounts,
                severity_definitions=parsed.severity_definitions,
                confirmed=True,
                source="authorization_response",
                evidence_response_id=resp.id,
            )
        )
        program.bounty_status = BountyStatus.CONFIRMED if available else BountyStatus.NOT_AVAILABLE
        if available:
            if parsed.max_bounty:
                program.max_bounty = parsed.max_bounty
                program.bounty_currency = parsed.bounty_currency
            audit.record(session, AuditEventType.BOUNTY_CONFIRMED, program.id, response_id=resp.id, max_bounty=parsed.max_bounty)
            notifications.notify(session, notifications.BOUNTY_CONFIRMED, f"Bounty confirmed for {program.name}.", program.id)
        changes.append(program.bounty_status)

    advance(session, program, settings)
    resp.applied_at = utcnow()
    program.last_verified = utcnow()
    program.opportunity_score = scoring.score(program, settings)
    audit.record(
        session,
        AuditEventType.AUTHORIZATION_RESPONSE_APPLIED,
        program.id,
        response_id=resp.id,
        actor=actor,
        changes=changes,
        state=program.authorization_status,
    )
    return changes


# --------------------------------------------------------------------------
# Manual confirmation (user-recorded evidence, e.g. a signed agreement)
# --------------------------------------------------------------------------

def confirm_authorization_manually(
    session: Session, program: Program, evidence: str, expires: datetime | None = None, settings: Settings | None = None
) -> None:
    if not evidence or len(evidence.strip()) < 10:
        raise AuthorizationError("manual authorization needs written evidence (link, quote or document reference)")
    settings = settings or get_settings()
    _grant(session, program, f"manual: {evidence.strip()}", expires, settings, "manual confirmation by user")
    advance(session, program, settings)


def confirm_scope_manually(session: Session, program: Program, scope_doc: dict, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    if program.authorized_at is None:
        raise AuthorizationError("record authorization before confirming scope")
    scope_engine.add_rules(session, program, scope_engine.parse_scope_document(scope_doc), "manual", True)
    if scope_engine.has_confirmed_in_scope_assets(program):
        program.scope_status = ScopeStatus.CONFIRMED
        notifications.notify(session, notifications.SCOPE_CHANGED, f"Scope confirmed for {program.name}.", program.id)
    advance(session, program, settings)


def confirm_bounty_manually(
    session: Session, program: Program, available: bool, max_bounty: float | None, currency: str | None, evidence: str,
    settings: Settings | None = None,
) -> None:
    settings = settings or get_settings()
    session.add(
        BountyTerms(program_id=program.id, available=available, max_bounty=max_bounty, currency=currency, confirmed=True, source=f"manual: {evidence}")
    )
    program.bounty_status = BountyStatus.CONFIRMED if available else BountyStatus.NOT_AVAILABLE
    if available:
        if max_bounty:
            program.max_bounty, program.bounty_currency = max_bounty, currency
        audit.record(session, AuditEventType.BOUNTY_CONFIRMED, program.id, source="manual", evidence=evidence)
        notifications.notify(session, notifications.BOUNTY_CONFIRMED, f"Bounty confirmed for {program.name}.", program.id)
    advance(session, program, settings)


# --------------------------------------------------------------------------
# State progression and expiry
# --------------------------------------------------------------------------

def gates_satisfied(program: Program, settings: Settings) -> list[str]:
    """Return unmet READY_FOR_RESEARCH requirements (empty = ready)."""
    missing = []
    if program.authorized_at is None or not program.authorization_evidence:
        missing.append("authorization")
    exp = as_utc(program.authorization_expires_at)
    if exp is not None and exp <= utcnow():
        missing.append("authorization expired")
    if program.scope_status != ScopeStatus.CONFIRMED or not scope_engine.has_confirmed_in_scope_assets(program):
        missing.append("confirmed scope")
    if settings.require_bounty_confirmation and program.bounty_status != BountyStatus.CONFIRMED:
        missing.append("bounty confirmation")
    return missing


def advance(session: Session, program: Program, settings: Settings | None = None) -> None:
    """Move forward as far as the recorded evidence allows."""
    settings = settings or get_settings()
    if program.authorized_at is None:
        return
    for _ in range(6):
        state = S(program.authorization_status)
        if state in (S.AUTHORIZED, S.SCOPE_UNCLEAR) and program.scope_status == ScopeStatus.CONFIRMED:
            transition(session, program, S.SCOPE_CONFIRMED, "scope confirmed")
        elif state in (S.SCOPE_CONFIRMED, S.BOUNTY_NOT_AVAILABLE) and program.bounty_status == BountyStatus.CONFIRMED:
            transition(session, program, S.BOUNTY_CONFIRMED, "bounty confirmed")
        elif state == S.SCOPE_CONFIRMED and program.bounty_status == BountyStatus.NOT_AVAILABLE:
            transition(session, program, S.BOUNTY_NOT_AVAILABLE, "bounty not available")
        elif state in (S.SCOPE_CONFIRMED, S.BOUNTY_CONFIRMED, S.BOUNTY_NOT_AVAILABLE) and not gates_satisfied(program, settings):
            transition(session, program, S.READY_FOR_RESEARCH, "all authorization gates satisfied")
        else:
            return


def expire_authorizations(session: Session) -> list[Program]:
    expired = []
    now = utcnow()
    for program in session.scalars(select(Program).where(Program.authorization_expires_at.is_not(None))):
        exp = as_utc(program.authorization_expires_at)
        if exp <= now and can_transition(program.authorization_status, S.EXPIRED_AUTHORIZATION):
            transition(session, program, S.EXPIRED_AUTHORIZATION, f"authorization expired {exp.isoformat()}")
            audit.record(session, AuditEventType.AUTHORIZATION_EXPIRED, program.id, expired_at=exp.isoformat())
            notifications.notify(
                session, notifications.AUTHORIZATION_EXPIRED, f"Authorization for {program.name} expired.", program.id
            )
            expired.append(program)
    return expired


def mark_no_response(session: Session, older_than_days: int = 30) -> list[Program]:
    cutoff = utcnow() - timedelta(days=older_than_days)
    out = []
    for program in session.scalars(select(Program).where(Program.authorization_status == S.AWAITING_RESPONSE)):
        sent = [as_utc(r.sent_at) for r in program.authorization_requests if r.sent_at]
        if sent and max(sent) < cutoff and not any(
            as_utc(resp.received_at) > max(sent) for r in program.authorization_requests for resp in r.responses
        ):
            transition(session, program, S.NO_RESPONSE, f"no reply in {older_than_days} days")
            out.append(program)
    return out


def match_inbound(session: Session, sender: str, subject: str) -> Program | None:
    """Match an inbound email to a program by subject or sender domain."""
    subject_l = (subject or "").lower()
    for req in session.scalars(select(AuthorizationRequest).where(AuthorizationRequest.status == RequestStatus.SENT)):
        if req.subject.lower() in subject_l:
            return session.get(Program, req.program_id)
    domain = sender.rsplit("@", 1)[-1].lower() if sender and "@" in sender else None
    if domain:
        for req in session.scalars(select(AuthorizationRequest).where(AuthorizationRequest.status == RequestStatus.SENT)):
            if req.recipient and req.recipient.lower().endswith("@" + domain):
                return session.get(Program, req.program_id)
    return None
