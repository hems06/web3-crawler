import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError

from crawler import audit
from crawler.config import PlatformConfig
from crawler.filters import ProgramFilter
from crawler.models import AuditEvent, Program


def test_reputation_based_is_a_program_property_not_a_platform_ban(session, discovered):
    pc = PlatformConfig.load()
    flt = ProgramFilter.from_settings(private_only=False)
    kept = {p.name for p in flt.apply(session.scalars(select(Program)).all(), pc)}
    # HackerOne defaults to reputation-gated invites -> excluded as reputation_based.
    assert "Invite H1" not in kept
    # HackenProof has a reputation system but this program does not require it.
    assert "Open DEX" in kept
    # Program-level evidence overrides the platform default.
    h1 = session.scalars(select(Program).where(Program.name == "Invite H1")).one()
    h1.platform_reputation_required = False
    kept = {p.name for p in flt.apply(session.scalars(select(Program)).all(), pc)}
    assert "Invite H1" in kept


def test_access_property_filters(session, discovered):
    pc = PlatformConfig.load()
    flt = ProgramFilter.from_settings(private_only=False, invite_required=True)
    flt.excluded_program_types = set()
    names = {p.name for p in flt.apply(session.scalars(select(Program)).all(), pc)}
    assert names == {"Invite H1"}


def test_private_only_and_extra_exclusions(session, discovered):
    pc = PlatformConfig.load()
    flt = ProgramFilter.from_settings(extra_exclusions=["direct"])
    assert flt.apply(session.scalars(select(Program)).all(), pc) == []


def test_undefined_excluded_type_is_rejected():
    with pytest.raises(ValueError):
        PlatformConfig({"excluded_program_types": ["nope"], "program_type_definitions": {}})


def test_audit_log_is_append_only(session, discovered):
    ok, bad = audit.verify_chain(session)
    assert ok, bad
    with pytest.raises(DatabaseError):
        session.execute(text("UPDATE audit_events SET event_type='x'"))
    session.rollback()
    with pytest.raises(DatabaseError):
        session.execute(text("DELETE FROM audit_events"))
    session.rollback()
    assert session.scalars(select(AuditEvent)).first() is not None


def test_scores_prefer_private_and_ignore_reputation(session, discovered):
    ex = session.scalars(select(Program).where(Program.name == "Example Protocol")).one()
    dex = session.scalars(select(Program).where(Program.name == "Open DEX")).one()
    assert 0 < dex.opportunity_score < ex.opportunity_score <= 100
