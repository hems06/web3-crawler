"""Gated research runner."""

from __future__ import annotations

import shutil
import subprocess

from sqlalchemy.orm import Session

from .. import audit
from ..config import Settings, get_settings
from ..enums import AuditEventType, ResearchMethod
from ..gate import require_authorization
from ..models import Finding, ResearchSession, utcnow

ETHERSCAN_PREFIX = {
    "Ethereum": "mainnet",
    "Arbitrum": "arbi",
    "Optimism": "optim",
    "Polygon": "poly",
    "Base": "base",
    "BNB Chain": "bsc",
    "Avalanche": "avax",
}


def start(
    session: Session, asset: str, method: ResearchMethod | str, program_id: int | None = None,
    chain: str | None = None, settings: Settings | None = None,
) -> ResearchSession:
    """Open a research session. Raises AuthorizationBlocked if any gate fails."""
    decision = require_authorization(session, asset, method, program_id=program_id, chain=chain, settings=settings)
    rs = ResearchSession(program_id=decision.program_id, asset=asset, method=decision.method, status="STARTED")
    session.add(rs)
    session.flush()
    audit.record(session, AuditEventType.RESEARCH_STARTED, decision.program_id, session_id=rs.id, asset=asset, method=decision.method)
    return rs


def run_static_analysis(
    session: Session, address: str, chain: str, program_id: int | None = None, settings: Settings | None = None
) -> ResearchSession:
    """Run Slither against a contract's verified source (fetched by
    crytic-compile from the explorer). Reads public source only."""
    settings = settings or get_settings()
    rs = start(session, address, ResearchMethod.STATIC_ANALYSIS, program_id, chain, settings)
    if not shutil.which("slither"):
        rs.status, rs.output = "FAILED", "slither is not installed"
    elif chain not in ETHERSCAN_PREFIX:
        rs.status, rs.output = "FAILED", f"no explorer prefix for chain {chain}"
    else:
        target = f"{ETHERSCAN_PREFIX[chain]}:{address}"
        cmd = ["slither", target, "--json", "-"]
        if settings.etherscan_api_key:
            cmd += ["--etherscan-apikey", settings.etherscan_api_key]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        rs.output = (proc.stdout or proc.stderr)[-200_000:]
        rs.status = "COMPLETED" if proc.returncode in (0, 255) else "FAILED"
    rs.finished_at = utcnow()
    session.flush()
    return rs


def create_finding(
    session: Session, research_session: ResearchSession, title: str, severity: str | None, description: str | None
) -> Finding:
    """Findings are drafts for the researcher to verify and report through
    the program's submission channel. Nothing is submitted automatically."""
    if research_session.status not in ("STARTED", "COMPLETED"):
        raise ValueError("findings can only come from a session that passed the gate")
    finding = Finding(
        program_id=research_session.program_id, session_id=research_session.id,
        title=title, severity=severity, description=description,
    )
    session.add(finding)
    session.flush()
    audit.record(session, AuditEventType.FINDING_CREATED, finding.program_id, finding_id=finding.id, title=title, severity=severity)
    return finding
