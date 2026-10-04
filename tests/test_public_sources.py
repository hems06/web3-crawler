import json

import httpx

from crawler import config, llm
from crawler.classifier import classify
from crawler.collectors.base import PoliteFetcher
from crawler.collectors.bounty_targets import BountyTargetsCollector, from_hackerone, from_intigriti, is_web3
from crawler.collectors.defillama import DefiLlamaSecurityTxtCollector, select_protocols
from crawler.enums import Classification
from crawler.normalizer import normalize

KW = ["crypto*", "blockchain*", "wallet", "swap", "coin*", "dao"]

H1 = {
    "handle": "chainx", "name": "ChainX", "url": "https://hackerone.com/chainx", "website": "https://chainx.example",
    "offers_bounties": True, "submission_state": "open",
    "targets": {
        "in_scope": [
            {"asset_identifier": "0x1111111111111111111111111111111111111111", "asset_type": "SMART_CONTRACT", "max_severity": "critical"},
            {"asset_identifier": "https://github.com/chainx/core", "asset_type": "SOURCE_CODE", "max_severity": "high"},
            {"asset_identifier": "*.chainx.example", "asset_type": "WILDCARD"},
        ],
        "out_of_scope": [{"asset_identifier": "blog.chainx.example", "asset_type": "URL"}],
    },
}


def test_web3_filter():
    assert is_web3(H1, KW)  # smart contract asset
    assert is_web3({"name": "Coinbase", "targets": {}}, KW)  # prefix keyword
    assert not is_web3({"name": "Swapcard", "targets": {}}, KW)  # whole-word keyword
    assert not is_web3({"name": "ADAC", "targets": {"in_scope": [{"type": "url", "endpoint": "adac.de"}]}}, KW)


def test_hackerone_listing_conversion():
    np = normalize(from_hackerone(H1), "bounty_targets")
    assert np.platform == "hackerone" and np.program_url == "https://hackerone.com/chainx"
    types = {s["type"] for s in np.listed_scope}
    assert types == {"contract", "repository", "domain"}
    assert np.platform_reputation_required is False and np.max_severity == "critical"
    assert classify(np)[0] == Classification.PUBLIC


def test_intigriti_application_program_is_private_possible():
    e = {"id": "x", "name": "DeFi Vault", "url": "https://www.intigriti.com/programs/v", "confidentiality_level": "application",
         "max_bounty": {"value": 20000, "currency": "EUR"}, "targets": {"in_scope": [{"type": "url", "endpoint": "app.vault.example"}]}}
    np = normalize(from_intigriti(e), "bounty_targets")
    assert np.application_required is True
    assert classify(np)[0] == Classification.PRIVATE_POSSIBLE


def _fetcher(handler):
    settings = config.get_settings()
    return PoliteFetcher(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_bounty_targets_collector_reads_dataset(set_env):
    def handler(req):
        if req.url.path.endswith("robots.txt"):
            return httpx.Response(404)
        if req.url.path.endswith("hackerone_data.json"):
            return httpx.Response(200, json=[H1, {"name": "Plain Shop", "handle": "shop", "targets": {}}])
        return httpx.Response(200, json=[])

    c = BountyTargetsCollector(config.get_settings(), fetcher=_fetcher(handler))
    rows = list(c.collect())
    assert [r["name"] for r in rows] == ["ChainX"]


PROTOCOLS = [
    {"name": "Big DEX", "slug": "big-dex", "url": "https://www.bigdex.example", "tvl": 5e9, "category": "Dexes", "chains": ["Ethereum", "Arbitrum"]},
    {"name": "Big DEX V2", "slug": "big-dex-v2", "url": "https://bigdex.example/v2", "tvl": 1e9, "category": "Dexes"},
    {"name": "Some CEX", "slug": "cex", "url": "https://cex.example", "tvl": 9e9, "category": "CEX"},
    {"name": "Lender", "slug": "lender", "url": "https://lender.example", "tvl": 2e9, "category": "Lending"},
    {"name": "Tiny", "slug": "tiny", "url": "https://tiny.example", "tvl": 10, "category": "Dexes"},
]


def test_select_protocols():
    chosen = select_protocols(PROTOCOLS, top_n=10, min_tvl=1e6, exclude_categories=["CEX"])
    assert [p["_host"] for p in chosen] == ["bigdex.example", "lender.example"]


def test_defillama_collector_finds_security_contacts():
    def handler(req):
        host, path = req.url.host, req.url.path
        if path == "/robots.txt":
            return httpx.Response(404)
        if host == "api.llama.fi":
            return httpx.Response(200, json=PROTOCOLS)
        if host == "bigdex.example" and path == "/.well-known/security.txt":
            return httpx.Response(200, text="Contact: mailto:security@bigdex.example\nPolicy: https://bigdex.example/security\n")
        if host == "lender.example" and path == "/.well-known/security.txt":
            return httpx.Response(200, text="Contact: mailto:sec@lender.example\nPolicy: https://immunefi.com/bounty/lender\n")
        if host == "lender.example":
            return httpx.Response(200, text="<html>not found page</html>")
        return httpx.Response(404)

    c = DefiLlamaSecurityTxtCollector(config.get_settings(), fetcher=_fetcher(handler))
    rows = {r["name"]: r for r in c.collect()}
    assert set(rows) == {"Big DEX", "Lender"}
    assert rows["Big DEX"]["security_email"] == "security@bigdex.example" and rows["Big DEX"]["platform"] == "direct"
    assert rows["Lender"]["platform"] == "immunefi"  # excluded by default config later
    np = normalize(rows["Big DEX"], "defillama_security_txt")
    assert classify(np)[0] == Classification.PRIVATE_POSSIBLE


PAGE = ("Big DEX security. Our bug bounty is invite-only; email security@bigdex.example to apply. "
        "Rewards up to $500,000 for critical issues. Core: 0x2222222222222222222222222222222222222222")


def test_llm_validation_drops_invented_values():
    data = {
        "program_type": "invite_only",
        "max_bounty": "$500,000",
        "max_severity": "critical",
        "security_email": "ceo@bigdex.example",  # not on the page
        "in_scope": [
            {"type": "contract", "value": "0x2222222222222222222222222222222222222222", "chain": "Ethereum"},
            {"type": "contract", "value": "0x3333333333333333333333333333333333333333"},  # invented
        ],
        "invite_required": True,
        "private_signals": ["invite-only"],
    }
    out = llm.validate(data, PAGE)
    assert "security_email" not in out
    assert [s["value"] for s in out["listed_scope"]] == ["0x2222222222222222222222222222222222222222"]
    assert out["program_type"] == "invite_only" and out["invite_required"] is True


def test_llm_extract_and_merge(set_env):
    s = set_env(OPENAI_API_KEY="sk-test", OPENAI_MODEL="test-model")
    seen = {}

    def handler(req):
        body = json.loads(req.content)
        seen["model"] = body["model"]
        seen["auth"] = req.headers["authorization"]
        content = json.dumps({"program_type": "invite_only", "max_bounty": "$500,000", "security_email": "security@bigdex.example", "private_signals": ["invite-only"]})
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    extracted = llm.extract_program(PAGE, "https://bigdex.example/security", s, client)
    assert seen == {"model": "test-model", "auth": "Bearer sk-test"}
    raw = llm.merge({"name": "Big DEX", "platform": "direct", "program_type": "unknown"}, extracted)
    np = normalize(raw, "defillama_security_txt")
    assert np.program_type.value == "invite_only" and np.max_bounty == 500000
    assert classify(np)[0] == Classification.PRIVATE_POSSIBLE


def test_llm_is_off_without_key_and_failures_are_harmless(set_env):
    assert llm.extract_program(PAGE, "u") == {}
    s = set_env(OPENAI_API_KEY="sk-test")
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    assert llm.extract_program(PAGE, "u", s, client) == {}
