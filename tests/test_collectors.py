from crawler.collectors.hackerone import HackerOneCollector
from crawler.collectors.program_page import extract_page
from crawler.collectors.security_txt import parse_security_txt, to_program
from crawler.classifier import classify
from crawler.enums import Classification
from crawler.normalizer import normalize, parse_money


def test_parse_money():
    assert parse_money("$50,000") == (50000.0, "USD")
    assert parse_money("Up to $1M") == (1_000_000.0, "USD")
    assert parse_money("250k USDC") == (250_000.0, "USDC")
    assert parse_money("unknown") == (None, None)


def test_security_txt():
    fields = parse_security_txt("# hi\nContact: mailto:security@example.com\nPolicy: https://example.com/policy\nExpires: 2027-01-01T00:00:00Z\n")
    prog = to_program("example.com", fields, "https://example.com/.well-known/security.txt")
    assert prog["security_email"] == "security@example.com"
    np = normalize(prog, "security_txt")
    cls, reasons = classify(np)
    assert cls == Classification.PRIVATE_POSSIBLE
    assert any("direct security-team" in r for r in reasons)


def test_program_page_extraction():
    html = """<html><head><title>Acme Security</title></head><body>
    <h1>Private bug bounty</h1><p>This program is invite-only. Rewards up to $250,000 for critical bugs.</p>
    <p>Contact security@acme.example to apply for access.</p>
    <p>Core: 0x1111111111111111111111111111111111111111 and github.com/acme/core</p></body></html>"""
    raw = extract_page("https://acme.example/security", html, "Acme")
    np = normalize(raw, "program_page")
    assert np.program_type.value == "invite_only"
    assert np.max_bounty == 250000
    assert np.security_email == "security@acme.example"
    assert {s["type"] for s in np.listed_scope} == {"contract", "repository"}
    assert classify(np)[0] == Classification.PRIVATE_POSSIBLE


def test_hackerone_private_invite_is_confirmed():
    item = {"attributes": {"handle": "acme", "name": "Acme", "state": "soft_launched", "submission_state": "open", "offers_bounties": True}}
    scopes = [{"asset_identifier": "0x1111111111111111111111111111111111111111", "asset_type": "SMART_CONTRACT", "eligible_for_submission": True}]
    np = normalize(HackerOneCollector.to_program(item, scopes), "hackerone")
    assert classify(np)[0] == Classification.PRIVATE_CONFIRMED
    assert np.listed_scope[0]["type"] == "contract"


def test_unlisted_hint_alone_is_only_possible():
    np = normalize({"name": "Hidden", "platform": "direct", "program_type": "private"}, "seed")
    assert classify(np)[0] == Classification.PRIVATE_POSSIBLE
