from types import SimpleNamespace as NS

from crawler.enums import AssetScope
from crawler.scope.engine import evaluate, parse_scope_document


def rule(rule_type, value, in_scope=True, confirmed=True, chain=None, id=1):
    return NS(rule_type=rule_type, value=value, in_scope=in_scope, confirmed=confirmed, chain=chain, id=id)


def test_unknown_asset_is_scope_unknown():
    rules = [rule("domain", "app.example.com")]
    assert evaluate(rules, "api.example.com").status == AssetScope.SCOPE_UNKNOWN


def test_subdomains_need_explicit_wildcard():
    assert evaluate([rule("domain", "example.com")], "app.example.com").status == AssetScope.SCOPE_UNKNOWN
    assert evaluate([rule("domain", "*.example.com")], "app.example.com").status == AssetScope.IN_SCOPE


def test_out_of_scope_wins():
    rules = [rule("domain", "*.example.com"), rule("domain", "legacy.example.com", in_scope=False)]
    assert evaluate(rules, "legacy.example.com").status == AssetScope.OUT_OF_SCOPE


def test_unconfirmed_listing_does_not_put_asset_in_scope():
    rules = [rule("domain", "app.example.com", confirmed=False)]
    assert evaluate(rules, "app.example.com").status == AssetScope.SCOPE_UNKNOWN
    assert evaluate(rules, "app.example.com", require_confirmed=False).status == AssetScope.IN_SCOPE


def test_contract_chain_must_match():
    addr = "0x00000000000000000000000000000000000000aa"
    rules = [rule("contract", addr, chain="Ethereum")]
    assert evaluate(rules, addr.upper().replace("0X", "0x"), chain="ethereum").status == AssetScope.IN_SCOPE
    assert evaluate(rules, addr, chain="Arbitrum").status == AssetScope.SCOPE_UNKNOWN
    assert evaluate(rules, addr).status == AssetScope.SCOPE_UNKNOWN


def test_repository_and_api_matching():
    rules = [rule("repository", "github.com/example/contracts"), rule("api", "https://api.example.com/v1")]
    assert evaluate(rules, "https://github.com/Example/contracts.git").status == AssetScope.IN_SCOPE
    assert evaluate(rules, "github.com/example/other").status == AssetScope.SCOPE_UNKNOWN
    assert evaluate(rules, "https://api.example.com/v1/users").status == AssetScope.IN_SCOPE
    assert evaluate(rules, "https://api.example.com/v2").status == AssetScope.SCOPE_UNKNOWN


def test_parse_scope_document():
    doc = {
        "scope": {
            "domains": ["example.com"],
            "contracts": ["0xAbC0000000000000000000000000000000000001", {"address": "0x0000000000000000000000000000000000000002", "chain": "arbitrum"}],
            "repositories": ["github.com/example/project"],
            "chains": ["Ethereum", "Arbitrum"],
            "out_of_scope": ["third_party_services", "production_users", "social_engineering", "denial_of_service", "old.example.com"],
        }
    }
    rules = parse_scope_document(doc)
    by = {(r["rule_type"], r["value"], r["in_scope"]) for r in rules}
    assert ("domain", "example.com", True) in by
    assert ("contract", "0xabc0000000000000000000000000000000000001", True) in by
    assert ("chain", "Arbitrum", True) in by
    assert ("category", "denial_of_service", False) in by
    assert ("domain", "old.example.com", False) in by
    assert any(r.get("chain") == "Arbitrum" for r in rules if r["rule_type"] == "contract")
