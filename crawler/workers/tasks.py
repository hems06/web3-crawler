"""Background tasks."""

from __future__ import annotations

import logging

from ..authorization import email_provider, manager
from ..config import get_settings
from ..db import session_scope
from ..gate import AuthorizationBlocked
from ..pipeline import discover as run_discovery
from ..research import runner
from .celery_app import app

log = logging.getLogger("crawler.tasks")


@app.task(name="crawler.workers.tasks.discover")
def discover() -> dict:
    with session_scope() as s:
        r = run_discovery(s)
        return {"new": len(r.new), "updated": len(r.updated), "errors": r.errors}


@app.task(name="crawler.workers.tasks.expire")
def expire() -> dict:
    with session_scope() as s:
        expired = manager.expire_authorizations(s)
        silent = manager.mark_no_response(s)
        return {"expired": [p.id for p in expired], "no_response": [p.id for p in silent]}


@app.task(name="crawler.workers.tasks.poll_inbox")
def poll_inbox() -> int:
    """Record replies to sent requests. Replies are never auto-applied."""
    if not get_settings().imap_host:
        return 0
    count = 0
    with session_scope() as s:
        for msg in email_provider.fetch_unseen():
            program = manager.match_inbound(s, msg.sender, msg.subject)
            if program is None:
                continue
            manager.record_response(s, program, msg.body, msg.sender, msg.subject)
            count += 1
    return count


@app.task(name="crawler.workers.tasks.run_research")
def run_research(address: str, chain: str, program_id: int) -> dict:
    """Only enqueued by an explicit user command. The gate is re-checked here,
    in the worker, so a queued job cannot outlive its authorization."""
    try:
        with session_scope() as s:
            rs = runner.run_static_analysis(s, address, chain, program_id)
            return {"session_id": rs.id, "status": rs.status}
    except AuthorizationBlocked as exc:
        log.warning("research blocked: %s", exc)
        return {"status": "BLOCKED", "reasons": exc.decision.reasons}
