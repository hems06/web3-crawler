"""FastAPI backend for the dashboard.

The API can read everything and perform the same user-driven authorization
steps as the CLI (draft, mark sent, record and apply a reply). It has no
endpoint that changes RESEARCH_MODE, edits the gate, marks a program
authorized without evidence, or starts research.
"""

from __future__ import annotations

from typing import Iterator

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import reporting
from ..authorization import manager, smtp_service
from ..authorization.state_machine import InvalidTransition
from ..config import PlatformConfig, get_settings
from ..db import get_sessionmaker
from ..enums import AuditEventType, AuthState
from ..filters import ProgramFilter
from ..gate import check_authorization
from ..models import (
    Asset,
    AuditEvent,
    AuthorizationRequest,
    AuthorizationResponse,
    Contract,
    Notification,
    Program,
)

app = FastAPI(title="Web3 Crawler", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://localhost:3000"], allow_methods=["*"], allow_headers=["*"])


def db() -> Iterator[Session]:
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _program(session: Session, program_id: int) -> Program:
    p = session.get(Program, program_id)
    if p is None:
        raise HTTPException(404, "program not found")
    return p


@app.get("/api/settings")
def settings_view():
    s = get_settings()
    pc = PlatformConfig.load(s)
    return {
        "research_mode": s.research_mode,
        "private_only": s.private_only,
        "require_bounty_confirmation": s.require_bounty_confirmation,
        "require_explicit_scope": s.require_explicit_scope,
        "authorization_expiry_days": s.authorization_expiry,
        "email_provider": smtp_service.effective_provider(s),
        "excluded_platforms": sorted(pc.excluded_platforms),
        "excluded_program_types": sorted(pc.excluded_program_types),
    }


@app.get("/api/programs")
def list_programs(
    private_only: bool | None = None,
    include_excluded: bool = False,
    session: Session = Depends(db),
):
    programs = session.scalars(select(Program).order_by(Program.opportunity_score.desc())).all()
    if not include_excluded:
        flt = ProgramFilter.from_settings(private_only=private_only)
        programs = flt.apply(programs)
    return [reporting.program_dict(p) for p in programs]


@app.get("/api/programs/{program_id}")
def get_program(program_id: int, session: Session = Depends(db)):
    p = _program(session, program_id)
    data = reporting.program_dict(p)
    data["gates_missing"] = manager.gates_satisfied(p, get_settings())
    return data


@app.get("/api/authorization")
def authorization_view(session: Session = Depends(db)):
    rows = []
    for p in session.scalars(select(Program)):
        reqs = sorted(p.authorization_requests, key=lambda r: r.id)
        if not reqs and p.authorized_at is None:
            continue
        last = reqs[-1] if reqs else None
        responses = session.scalars(
            select(AuthorizationResponse).where(AuthorizationResponse.program_id == p.id).order_by(AuthorizationResponse.id)
        ).all()
        rows.append(
            {
                "program_id": p.id,
                "project": p.name,
                "authorization_status": p.authorization_status,
                "indicator": reporting.program_dict(p)["indicator"],
                "email_status": last.status if last else None,
                "request_id": last.id if last else None,
                "recipient": last.recipient if last else None,
                "date_requested": last.created_at if last else None,
                "date_sent": last.sent_at if last else None,
                "response_status": responses[-1].classifications if responses else None,
                "responses": [
                    {"id": r.id, "received_at": r.received_at, "sender": r.sender, "classifications": r.classifications,
                     "applied": r.applied_at is not None}
                    for r in responses
                ],
                "authorization_evidence": p.authorization_evidence,
                "authorization_expires_at": p.authorization_expires_at,
                "scope_confirmation": p.scope_status,
                "bounty_confirmation": p.bounty_status,
            }
        )
    return rows


@app.get("/api/requests/{request_id}")
def get_request(request_id: int, session: Session = Depends(db)):
    r = session.get(AuthorizationRequest, request_id)
    if r is None:
        raise HTTPException(404)
    return {"id": r.id, "program_id": r.program_id, "recipient": r.recipient, "subject": r.subject, "body": r.body,
            "status": r.status, "created_at": r.created_at, "sent_at": r.sent_at}


class GenerateBody(BaseModel):
    recipient: str | None = None


@app.post("/api/programs/{program_id}/authorization-request")
def generate_request(program_id: int, body: GenerateBody, session: Session = Depends(db)):
    """Draft an email. Drafting never sends anything."""
    try:
        r = manager.generate_request(session, _program(session, program_id), body.recipient)
    except InvalidTransition as exc:
        raise HTTPException(409, str(exc))
    return {"id": r.id, "subject": r.subject, "body": r.body, "recipient": r.recipient, "status": r.status}


@app.post("/api/requests/{request_id}/mark-sent")
def mark_sent(request_id: int, session: Session = Depends(db)):
    """The user sent the draft from their own mail client."""
    r = session.get(AuthorizationRequest, request_id)
    if r is None:
        raise HTTPException(404)
    try:
        manager.mark_sent_manually(session, r)
    except (manager.AuthorizationError, InvalidTransition) as exc:
        raise HTTPException(409, str(exc))
    return {"id": r.id, "status": r.status}


class ResponseBody(BaseModel):
    body: str
    sender: str | None = None
    subject: str | None = None


@app.post("/api/programs/{program_id}/responses")
def record_response(program_id: int, payload: ResponseBody, session: Session = Depends(db)):
    resp = manager.record_response(session, _program(session, program_id), payload.body, payload.sender, payload.subject)
    return {"id": resp.id, "classifications": resp.classifications, "extracted": resp.extracted}


@app.post("/api/responses/{response_id}/apply")
def apply_response(response_id: int, session: Session = Depends(db)):
    resp = session.get(AuthorizationResponse, response_id)
    if resp is None:
        raise HTTPException(404)
    try:
        changes = manager.apply_response(session, resp, actor="dashboard")
    except (manager.AuthorizationError, InvalidTransition) as exc:
        raise HTTPException(409, str(exc))
    return {"changes": changes, "program": reporting.program_dict(session.get(Program, resp.program_id))}


@app.get("/api/scope")
def scope_view(session: Session = Depends(db)):
    out = []
    for p in session.scalars(select(Program)):
        if not p.scope_rules:
            continue
        grouped: dict[str, list] = {"domains": [], "contracts": [], "repositories": [], "chains": [], "apis": [], "out_of_scope": []}
        key = {"domain": "domains", "contract": "contracts", "repository": "repositories", "chain": "chains", "api": "apis", "rpc": "apis"}
        for r in p.scope_rules:
            item = {"value": r.value, "chain": r.chain, "confirmed": r.confirmed, "source": r.source}
            if not r.in_scope:
                grouped["out_of_scope"].append(item)
            elif r.rule_type in key:
                grouped[key[r.rule_type]].append(item)
        out.append({"program_id": p.id, "project": p.name, "scope_status": p.scope_status,
                    "restrictions": p.testing_restrictions, "prohibited_methods": p.prohibited_methods, **grouped})
    return out


@app.get("/api/programs/{program_id}/assets")
def program_assets(program_id: int, session: Session = Depends(db)):
    _program(session, program_id)
    assets = session.scalars(select(Asset).where(Asset.program_id == program_id)).all()
    contracts = session.scalars(select(Contract).where(Contract.program_id == program_id)).all()
    return {
        "assets": [{"id": a.id, "type": a.asset_type, "identifier": a.identifier, "chain": a.chain, "scope_status": a.scope_status, "source": a.source} for a in assets],
        "contracts": [{c.key: getattr(x, c.key) for c in Contract.__table__.columns} for x in contracts],
    }


@app.get("/api/research-ready")
def research_ready(session: Session = Depends(db)):
    s = get_settings()
    ready = [
        p for p in session.scalars(select(Program).where(Program.authorization_status == AuthState.READY_FOR_RESEARCH))
        if not manager.gates_satisfied(p, s)
    ]
    return {"research_mode": s.research_mode, "programs": [reporting.program_dict(p) for p in ready]}


@app.get("/api/blocked")
def blocked(limit: int = 100, session: Session = Depends(db)):
    rows = session.scalars(
        select(AuditEvent).where(AuditEvent.event_type == AuditEventType.RESEARCH_BLOCKED).order_by(AuditEvent.id.desc()).limit(limit)
    )
    return [e.payload for e in rows]


@app.get("/api/audit")
def audit_log(limit: int = 200, session: Session = Depends(db)):
    rows = session.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit))
    return [{"id": e.id, "created_at": e.created_at, "event_type": e.event_type, "program_id": e.program_id, "payload": e.payload} for e in rows]


@app.get("/api/notifications")
def notifications(limit: int = 100, session: Session = Depends(db)):
    rows = session.scalars(select(Notification).order_by(Notification.id.desc()).limit(limit))
    return [{"id": n.id, "created_at": n.created_at, "kind": n.kind, "message": n.message, "program_id": n.program_id, "read": n.read} for n in rows]


class GateCheck(BaseModel):
    asset: str
    method: str
    program_id: int | None = None
    chain: str | None = None


@app.post("/api/gate/check")
def gate_check(payload: GateCheck, session: Session = Depends(db)):
    """Read-only question to the gate. It can report a decision; it cannot
    change one. Blocked checks are logged like any other."""
    d = check_authorization(session, payload.asset, payload.method, program_id=payload.program_id, chain=payload.chain)
    return d.as_event()


@app.get("/api/health")
def health():
    return {"ok": True}
