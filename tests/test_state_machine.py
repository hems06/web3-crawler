import pytest

from crawler.authorization.state_machine import InvalidTransition, can_transition, transition
from crawler.enums import AuthState as S


def test_cannot_skip_authorization():
    assert not can_transition(S.DISCOVERED, S.AUTHORIZED)
    assert not can_transition(S.PRIVATE_CANDIDATE, S.READY_FOR_RESEARCH)
    assert not can_transition(S.AWAITING_RESPONSE, S.SCOPE_CONFIRMED)
    assert not can_transition(S.AUTHORIZED, S.READY_FOR_RESEARCH)
    assert not can_transition(S.NOT_AUTHORIZED, S.AUTHORIZED)


def test_happy_path_is_allowed():
    path = [S.DISCOVERED, S.PRIVATE_CANDIDATE, S.AUTHORIZATION_REQUESTED, S.AWAITING_RESPONSE,
            S.AUTHORIZED, S.SCOPE_CONFIRMED, S.BOUNTY_CONFIRMED, S.READY_FOR_RESEARCH]
    for a, b in zip(path, path[1:]):
        assert can_transition(a, b), (a, b)


def test_ready_requires_evidence(session, discovered):
    from crawler.models import Program
    from sqlalchemy import select

    p = session.scalars(select(Program).where(Program.name == "Example Protocol")).one()
    p.authorization_status = S.BOUNTY_CONFIRMED  # forced for the test
    with pytest.raises(InvalidTransition):
        transition(session, p, S.READY_FOR_RESEARCH, "test")
