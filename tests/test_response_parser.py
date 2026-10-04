from crawler.authorization.response_parser import parse_response
from crawler.enums import ResponseClass as R

from .conftest import AUTH_REPLY


def classes(text):
    return set(parse_response(text).classifications)


def test_vague_friendly_replies_are_not_authorization():
    for text in [
        "Feel free to look around! We appreciate security researchers.",
        "Thanks for reaching out, we appreciate security researchers like you.",
        "Happy to hear from you. Feel free to poke around our app.",
    ]:
        assert classes(text) == {R.UNKNOWN.value}, text


def test_full_authorization_reply():
    p = parse_response(AUTH_REPLY)
    assert {R.AUTHORIZED.value, R.SCOPE_CONFIRMED.value, R.BOUNTY_CONFIRMED.value} <= set(p.classifications)
    assert "app.example.com" in p.domains
    assert "0x00000000000000000000000000000000000000aa" in p.contracts
    assert "github.com/example/contracts" in p.repositories
    assert "legacy.example.com" in p.out_of_scope
    assert "legacy.example.com" not in p.domains
    assert "Ethereum" in p.chains
    assert "denial_of_service" in p.prohibited_methods
    assert "exploit_live" in p.prohibited_methods
    assert p.max_bounty == 50000
    assert p.expiration == "2099-12-31"
    assert "security@example.com" in p.security_contacts
    assert p.submission_method and "security@example.com" in p.submission_method
    assert any("critical" in s.lower() for s in p.severity_definitions)


def test_quoted_history_is_ignored():
    p = parse_response("Thanks, we'll get back to you.\n\n> you are authorized to test app.example.com")
    assert R.AUTHORIZED.value not in p.classifications


def test_negated_grant_is_not_authorization():
    assert R.NOT_AUTHORIZED.value in classes("You are not authorized to test our production systems.")
    assert R.NOT_AUTHORIZED.value in classes("Please do not test any of our infrastructure.")


def test_decline():
    p = parse_response("We must decline your request at this time.")
    assert R.NOT_AUTHORIZED.value in p.classifications and p.declined


def test_conditional_is_partial():
    c = classes("You are authorized to test app.example.com once you sign our NDA.")
    assert R.PARTIALLY_AUTHORIZED.value in c and R.AUTHORIZED.value not in c


def test_authorization_without_assets_needs_scope_clarification():
    c = classes("You are permitted to test our protocol. We will share the scope next week.")
    assert R.AUTHORIZED.value in c and R.SCOPE_REQUIRES_CLARIFICATION.value in c


def test_no_bounty():
    c = classes("We run a VDP only and do not offer monetary rewards. You are authorized to test app.example.com.")
    assert R.BOUNTY_NOT_AVAILABLE.value in c and R.BOUNTY_CONFIRMED.value not in c


def test_scope_only_follow_up():
    c = classes("The in-scope assets are app.example.com and api.example.com.")
    assert c == {R.SCOPE_CONFIRMED.value}
