"""End-to-end: discovery -> email -> reply -> gates -> research gate."""

from datetime import timedelta

import pytest
from sqlalchemy import select

from crawler.authorization import manager
from crawler.enums import AuditEventType, AuthState as S, BountyStatus, Classification, RequestStatus, ScopeStatus
from crawler.gate import AuthorizationBlocked, check_authorization
from crawler.models import AuditEvent, Notification, Program, ResearchSession, utcnow
from crawler.research import runner

from .conftest import AUTH_REPLY

ADDR = "0x00000000000000000000000000000000000000aa"


def get(session, name):
    return session.scalars(select(Program).where(Program.name == name)).one()


def events(session, kind):
    return session.scalars(select(AuditEvent).where(AuditEvent.event_type == kind)).all()


def test_discovery_classifies_and_excludes(session, discovered):
    names = {p.name for p in session.scalars(select(Program))}
    assert "Immunefi Thing" not in names  # excluded platform, never stored
    ex = get(session, "Example Protocol")
    assert ex.classification == Classification.PRIVATE_POSSIBLE
    assert ex.authorization_status == S.PRIVATE_CANDIDATE
    assert ex.scope_status == ScopeStatus.LISTED
    assert ex.bounty_status == BountyStatus.LISTED
    assert ex.max_bounty == 50000
    assert all(not r.confirmed for r in ex.scope_rules)
    assert get(session, "Invite H1").classification == Classification.PRIVATE_CONFIRMED
    assert get(session, "Open DEX").classification == Classification.PUBLIC
    assert events(session, AuditEventType.PROGRAM_DISCOVERED)
    assert session.scalars(select(Notification).where(Notification.kind == "private_program_discovered")).all()


def test_discovered_private_program_is_not_testable(session, discovered):
    ex = get(session, "Example Protocol")
    d = check_authorization(session, "app.example.com", "static_analysis", program_id=ex.id)
    assert not d.allowed and "NOT_AUTHORIZED" in d.reasons and "SCOPE_UNKNOWN" in d.reasons


def _authorize(session, set_env=None):
    ex = get(session, "Example Protocol")
    req = manager.generate_request(session, ex)
    assert req.status == RequestStatus.DRAFT and req.recipient == "security@example.com"
    assert "Before performing any testing" in req.body and "8. Whether there is a preferred security contact" in req.body
    assert ex.authorization_status == S.AUTHORIZATION_REQUESTED
    manager.mark_sent_manually(session, req)
    assert ex.authorization_status == S.AWAITING_RESPONSE
    resp = manager.record_response(session, ex, AUTH_REPLY, "alice@example.com", "Re: " + req.subject)
    assert ex.authorization_status == S.AWAITING_RESPONSE  # not applied yet
    manager.apply_response(session, resp)
    session.commit()
    return ex


def test_full_authorization_flow(session, discovered):
    ex = _authorize(session)
    assert ex.authorization_status == S.READY_FOR_RESEARCH
    assert ex.scope_status == ScopeStatus.CONFIRMED and ex.bounty_status == BountyStatus.CONFIRMED
    assert ex.authorization_expires_at.year == 2099
    assert "denial_of_service" in ex.prohibited_methods
    states = [e.payload["to_state"] for e in events(session, AuditEventType.AUTHORIZATION_STATE_CHANGED) if e.program_id == ex.id]
    assert states[-4:] == ["AUTHORIZED", "SCOPE_CONFIRMED", "BOUNTY_CONFIRMED", "READY_FOR_RESEARCH"]


def test_gate_blocks_until_research_mode(session, discovered, set_env):
    ex = _authorize(session)
    d = check_authorization(session, ADDR, "static_analysis", program_id=ex.id, chain="Ethereum")
    assert d.reasons == ["RESEARCH_MODE_DISABLED"]
    set_env(RESEARCH_MODE="true")
    d = check_authorization(session, ADDR, "static_analysis", program_id=ex.id, chain="Ethereum")
    assert d.allowed, d.reasons
    # asset resolution without program id
    assert check_authorization(session, ADDR, "static_analysis", chain="Ethereum").allowed


def test_gate_conditions(session, discovered, set_env):
    ex = _authorize(session)
    set_env(RESEARCH_MODE="true")
    # 4. asset outside scope
    assert "SCOPE_UNKNOWN" in check_authorization(session, "api.example.com", "static_analysis", program_id=ex.id).reasons
    assert "OUT_OF_SCOPE" in check_authorization(session, "legacy.example.com", "static_analysis", program_id=ex.id).reasons
    # 5. methods
    assert "METHOD_PROHIBITED" in check_authorization(session, "app.example.com", "denial_of_service", program_id=ex.id).reasons
    assert "METHOD_PROHIBITED" in check_authorization(session, "app.example.com", "brute_force", program_id=ex.id).reasons
    assert "METHOD_NOT_PERMITTED" in check_authorization(session, "app.example.com", "active_scan", program_id=ex.id).reasons
    # 1. program missing
    assert "PROGRAM_NOT_FOUND" in check_authorization(session, "app.example.com", "static_analysis", program_id=9999).reasons
    # 3. expiry
    ex.authorization_expires_at = utcnow() - timedelta(seconds=1)
    assert "AUTHORIZATION_EXPIRED" in check_authorization(session, ADDR, "static_analysis", program_id=ex.id, chain="Ethereum").reasons
    blocked = events(session, AuditEventType.RESEARCH_BLOCKED)
    assert blocked and blocked[-1].payload["action"] == "BLOCKED" and blocked[-1].payload["event"] == "AuthorizationBlockedEvent"
    assert session.scalars(select(ResearchSession).where(ResearchSession.status == "BLOCKED")).all()


def test_bounty_requirement(session, discovered, set_env):
    ex = get(session, "Example Protocol")
    req = manager.generate_request(session, ex)
    manager.mark_sent_manually(session, req)
    resp = manager.record_response(session, ex, "You are authorized to test app.example.com. We do not offer monetary rewards.")
    manager.apply_response(session, resp)
    assert ex.authorization_status == S.BOUNTY_NOT_AVAILABLE
    set_env(RESEARCH_MODE="true")
    assert check_authorization(session, "app.example.com", "static_analysis", program_id=ex.id).reasons == ["BOUNTY_NOT_CONFIRMED"]
    set_env(RESEARCH_MODE="true", REQUIRE_BOUNTY_CONFIRMATION="false")
    assert check_authorization(session, "app.example.com", "static_analysis", program_id=ex.id).allowed


def test_vague_reply_unlocks_nothing(session, discovered):
    ex = get(session, "Example Protocol")
    req = manager.generate_request(session, ex)
    manager.mark_sent_manually(session, req)
    resp = manager.record_response(session, ex, "Feel free to look around app.example.com! We appreciate security researchers.")
    manager.apply_response(session, resp)
    assert ex.authorization_status == S.AWAITING_RESPONSE
    assert ex.authorized_at is None and ex.scope_status == ScopeStatus.LISTED


def test_denial_revokes(session, discovered):
    ex = _authorize(session)
    resp = manager.record_response(session, ex, "Please do not test our systems. You are not authorized to test.")
    manager.apply_response(session, resp)
    assert ex.authorization_status == S.NOT_AUTHORIZED and ex.authorized_at is None


def test_expiry_job(session, discovered):
    ex = _authorize(session)
    ex.authorization_expires_at = utcnow() - timedelta(days=1)
    expired = manager.expire_authorizations(session)
    assert ex in expired and ex.authorization_status == S.EXPIRED_AUTHORIZATION
    assert session.scalars(select(Notification).where(Notification.kind == "authorization_expired")).all()


def test_research_runner_is_gated(session, discovered):
    ex = _authorize(session)
    with pytest.raises(AuthorizationBlocked):
        runner.start(session, ADDR, "static_analysis", program_id=ex.id, chain="Ethereum")
    # the blocked event survives a rollback
    session.rollback()
    assert events(session, AuditEventType.RESEARCH_BLOCKED)


def test_email_is_never_sent_without_approval(session, discovered, set_env):
    set_env(EMAIL_PROVIDER="smtp", SMTP_HOST="smtp.invalid")
    ex = get(session, "Example Protocol")
    req = manager.generate_request(session, ex)
    sent = []
    with pytest.raises(manager.AuthorizationError):
        manager.send_request(session, req, sender=lambda *a: sent.append(a))
    manager.approve_request(session, req)
    manager.send_request(session, req, sender=lambda *a: sent.append(a))
    assert len(sent) == 1 and req.status == RequestStatus.SENT
    assert ex.authorization_status == S.AWAITING_RESPONSE


def test_manual_confirmation_requires_evidence(session, discovered):
    ex = get(session, "Open DEX")
    with pytest.raises(manager.AuthorizationError):
        manager.confirm_authorization_manually(session, ex, "ok")
    manager.confirm_authorization_manually(session, ex, "https://hackenproof.com/dex policy, accepted terms 2026-10-01")
    assert ex.authorization_status == S.AUTHORIZED
    with pytest.raises(manager.AuthorizationError):
        manager.confirm_scope_manually(session, get(session, "Example Protocol"), {"domains": ["x.example.com"]})
    manager.confirm_scope_manually(session, ex, {"scope": {"domains": ["dex.example.org"]}})
    assert ex.authorization_status == S.SCOPE_CONFIRMED
    manager.confirm_bounty_manually(session, ex, True, 10000, "USD", "policy page")
    assert ex.authorization_status == S.READY_FOR_RESEARCH
