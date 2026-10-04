import json

import httpx
from click.testing import CliRunner

from crawler import cli, config, llm, user_config
from crawler.collectors.bounty_targets import BountyTargetsCollector
from crawler.collectors.defillama import DefiLlamaSecurityTxtCollector, security_links

from .test_public_sources import H1, _fetcher


def _settings():
    config.get_settings.cache_clear()
    return config.get_settings()


# ------------------------------------------------------------------ setup
def test_setup_saves_answers_once(monkeypatch):
    monkeypatch.setattr(llm, "check_key", lambda s: None)
    # name, contact, skip SMTP, API key, model
    answers = "Ada\nada@example.org\nn\nsk-live-123\ngpt-4o\n"
    result = CliRunner().invoke(cli.main, ["setup"], input=answers)
    assert result.exit_code == 0, result.output
    assert "Key works." in result.output and "won't be asked again" in result.output
    assert user_config.setup_done()
    s = _settings()
    assert (s.researcher_name, s.researcher_contact, s.openai_api_key, s.openai_model) == ("Ada", "ada@example.org", "sk-live-123", "gpt-4o")

    shown = CliRunner().invoke(cli.main, ["setup", "--show"])
    assert "openai_api_key: set" in shown.output and "sk-live-123" not in shown.output
    assert oct(user_config.path().stat().st_mode & 0o777) == "0o600"


def test_saved_values_beat_dotenv_but_not_env(tmp_path, monkeypatch, set_env):
    user_config.save({"researcher_name": "Saved", "openai_api_key": "sk-saved"})
    (tmp_path / ".env").write_text("RESEARCHER_NAME=Your Name\nOPENAI_API_KEY=\n")
    s = _settings()
    assert s.researcher_name == "Saved" and s.openai_api_key == "sk-saved"
    assert set_env(OPENAI_API_KEY="sk-env").openai_api_key == "sk-env"


def test_first_run_prompt_only_on_a_terminal(monkeypatch):
    assert not cli._should_offer_setup()  # tests are not a TTY
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    assert cli._should_offer_setup()
    user_config.save({"setup_completed": True})
    assert not cli._should_offer_setup()


def test_skipping_everything_still_marks_setup_done():
    result = CliRunner().invoke(cli.main, ["setup"], input="\n\nn\n\n")
    assert result.exit_code == 0, result.output
    assert user_config.setup_done() and not _settings().openai_api_key


def test_forget_openai_key():
    user_config.save({"openai_api_key": "sk-x", "setup_completed": True})
    CliRunner().invoke(cli.main, ["setup", "--forget-openai-key"])
    assert not _settings().openai_api_key and user_config.setup_done()


# -------------------------------------------------------------------- llm
def test_focus_text_keeps_program_details():
    filler = "Swap tokens fast with our app today. " * 600
    page = filler + "The bug bounty pays up to $1,000,000 for critical bugs. Email security@x.example. " + filler
    out = llm.focus_text(page, limit=2000)
    assert len(out) <= 2000 and "$1,000,000" in out and "security@x.example" in out
    assert llm.focus_text("short page") == "short page"


def _reply(payload):
    return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(payload)}}]})


def test_extraction_is_cached(set_env):
    s = set_env(OPENAI_API_KEY="sk-test")
    calls = []

    def handler(req):
        calls.append(1)
        return _reply({"program_type": "public", "max_bounty": "$5,000"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    page = "Bug bounty up to $5,000."
    assert llm.extract_program(page, "https://a.example/sec", s, client)["max_bounty"] == "$5,000"
    assert llm.extract_program(page, "https://a.example/sec", s, client)["max_bounty"] == "$5,000"
    assert len(calls) == 1
    llm.extract_program(page + " Changed.", "https://a.example/sec", s, client)
    assert len(calls) == 2


def test_classify_web3_batches_and_caches(set_env, monkeypatch):
    s = set_env(OPENAI_API_KEY="sk-test")
    monkeypatch.setattr(llm, "CLASSIFY_BATCH", 2)
    seen = []

    def handler(req):
        items = json.loads(json.loads(req.content)["messages"][1]["content"])
        seen.append(len(items))
        # Web3 = names starting with "Chain"; also an out-of-range index to ignore.
        return _reply({"web3": [it["i"] for it in items if it["name"].startswith("Chain")] + [99]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    items = [{"name": n, "website": "", "targets": []} for n in ("Chainlet", "Shop", "ChainPay")]
    assert llm.classify_web3(items, s, client) == [True, False, True]
    assert seen == [2, 1]
    assert llm.classify_web3(items, s, client) == [True, False, True]
    assert seen == [2, 1]  # answered from cache


def test_bounty_targets_asks_model_about_keyword_misses(set_env, monkeypatch):
    set_env(OPENAI_API_KEY="sk-test")
    plain = {"handle": "ledgerly", "name": "Ledgerly", "url": "https://hackerone.com/ledgerly", "offers_bounties": True, "targets": {}}
    shop = {"handle": "shop", "name": "Plain Shop", "url": "https://hackerone.com/shop", "targets": {}}
    asked = []

    def fake_classify(items, settings=None, client=None):
        asked.extend(i["name"] for i in items)
        return [i["name"] == "Ledgerly" for i in items]

    monkeypatch.setattr(llm, "classify_web3", fake_classify)

    def handler(req):
        if req.url.path.endswith("robots.txt"):
            return httpx.Response(404)
        if req.url.path.endswith("hackerone_data.json"):
            return httpx.Response(200, json=[H1, plain, shop])
        return httpx.Response(200, json=[])

    rows = list(BountyTargetsCollector(config.get_settings(), fetcher=_fetcher(handler)).collect())
    assert [r["name"] for r in rows] == ["ChainX", "Ledgerly"]
    assert asked == ["Ledgerly", "Plain Shop"]  # ChainX matched without the model
    assert "model review" in rows[1]["notes"]


HOME = """<html><body><a href="/docs">Docs</a><a href="/security">Security</a>
<a href="https://immunefi.com/bug-bounty/vaultx">Bug bounty</a></body></html>"""


def test_security_links_ranked():
    links = security_links(HOME, "https://vaultx.example/")
    assert links[0] == "https://immunefi.com/bug-bounty/vaultx"
    assert "https://vaultx.example/security" in links and "https://vaultx.example/docs" not in links


def test_defillama_homepage_fallback(set_env, monkeypatch):
    set_env(OPENAI_API_KEY="sk-test")
    protocols = [{"name": "Lendr", "slug": "lendr", "url": "https://lendr.example", "tvl": 5e9, "category": "Lending"}]
    page = "<html><body>Security. Report vulnerabilities to security@lendr.example. Bug bounty by invitation only.</body></html>"
    monkeypatch.setattr(llm, "extract_program", lambda text, url, settings=None, client=None: {"program_type": "invite_only", "max_bounty": "$100,000"})

    def handler(req):
        host, path = req.url.host, req.url.path
        if path == "/robots.txt":
            return httpx.Response(404)
        if host == "api.llama.fi":
            return httpx.Response(200, json=protocols)
        if host == "lendr.example" and path == "/":
            return httpx.Response(200, text='<a href="/security">Security</a>', headers={"content-type": "text/html"})
        if host == "lendr.example" and path == "/security":
            return httpx.Response(200, text=page, headers={"content-type": "text/html"})
        return httpx.Response(404)

    rows = list(DefiLlamaSecurityTxtCollector(config.get_settings(), fetcher=_fetcher(handler)).collect())
    assert len(rows) == 1
    r = rows[0]
    assert r["security_email"] == "security@lendr.example" and r["program_url"] == "https://lendr.example/security"
    assert r["program_type"] == "invite_only" and r["extracted_by"] == "openai"


# ------------------------------------------------------------- 429 handling
def _err(status, code, headers=None):
    return httpx.Response(status, json={"error": {"code": code, "type": code, "message": "x"}}, headers=headers or {})


def test_rate_limit_is_retried_with_retry_after(set_env, monkeypatch):
    s = set_env(OPENAI_API_KEY="sk-test")
    waits, calls = [], []
    monkeypatch.setattr(llm, "_sleep", waits.append)

    def handler(req):
        calls.append(1)
        if len(calls) < 3:
            return _err(429, "rate_limit_exceeded", {"retry-after": "1.5"})
        return _reply({"program_type": "public"})

    out = llm.extract_program("Bug bounty page.", "https://r.example", s, httpx.Client(transport=httpx.MockTransport(handler)))
    assert out["program_type"] == "public" and waits == [1.5, 1.5] and llm.enabled(s)


def test_no_quota_turns_model_off_once(set_env, caplog):
    s = set_env(OPENAI_API_KEY="sk-test")
    calls = []

    def handler(req):
        calls.append(1)
        return _err(429, "insufficient_quota")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    items = [{"name": "A", "website": "", "targets": []}]
    with caplog.at_level("WARNING", logger="crawler.llm"):
        assert llm.classify_web3(items, s, client) == [False]
        assert llm.extract_program("Bug bounty.", "https://q.example", s, client) == {}
        assert llm.extract_program("Bug bounty 2.", "https://q.example", s, client) == {}
    assert len(calls) == 1  # no retries for quota, and no calls after turning off
    assert not llm.enabled(s) and "no credit" in llm.disabled_reason()
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1 and "Crawling continues without it" in warnings[0].getMessage()
    llm.reset()
    assert llm.enabled(s)


def test_persistent_rate_limit_turns_model_off(set_env):
    s = set_env(OPENAI_API_KEY="sk-test")
    client = httpx.Client(transport=httpx.MockTransport(lambda r: _err(429, "rate_limit_exceeded")))
    assert llm.extract_program("Bug bounty.", "https://p.example", s, client) == {}
    assert "rate limiting" in llm.disabled_reason()


def test_repeated_other_failures_turn_model_off(set_env):
    s = set_env(OPENAI_API_KEY="sk-test")
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    for i in range(llm.MAX_CONSECUTIVE_FAILURES):
        llm.extract_program(f"Bug bounty {i}.", "https://p.example", s, client)
    assert not llm.enabled(s) and "in a row" in llm.disabled_reason()


# ------------------------------------------------- progress, timeouts, Ctrl+C
def test_rate_limit_waits_are_capped_per_run(set_env, monkeypatch):
    s = set_env(OPENAI_API_KEY="sk-test", LLM_MAX_WAIT_SECONDS=60)
    waits = []
    monkeypatch.setattr(llm, "_sleep", waits.append)
    client = httpx.Client(transport=httpx.MockTransport(lambda r: _err(429, "rate_limit_exceeded", {"retry-after": "25"})))
    assert llm.extract_program("Bug bounty.", "https://w.example", s, client) == {}
    assert waits == [25, 25]  # a third wait would pass the 60s cap
    assert not llm.enabled(s)


def test_fetch_has_a_hard_deadline(set_env):
    import time as _time

    import pytest

    from crawler.collectors.base import PoliteFetcher

    s = set_env(FETCH_TIMEOUT_SECONDS="0.2")

    class Slow(httpx.SyncByteStream):
        def __iter__(self):
            for _ in range(50):
                _time.sleep(0.02)
                yield b"x"

    def handler(req):
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(200, stream=Slow())

    f = PoliteFetcher(s, client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(httpx.ReadTimeout):
        f.get("https://slow.example/page")


def test_ctrl_c_keeps_programs_found_so_far(session):
    from crawler.models import Program
    from crawler.pipeline import discover

    from .conftest import SEED

    class Interrupted:
        name = "test"
        progress = None

        def enabled(self):
            return True

        def collect(self):
            yield SEED
            raise KeyboardInterrupt

    messages = []
    result = discover(session, [Interrupted()], progress=lambda m, transient=False: messages.append(m))
    assert result.interrupted and len(result.new) == 1
    assert session.query(Program).count() == 1
    assert messages == ["Reading test..."]


def test_collectors_report_progress(set_env):
    from crawler.pipeline import discover

    seen = []

    def handler(req):
        if req.url.path.endswith("robots.txt"):
            return httpx.Response(404)
        return httpx.Response(200, json=[H1] if "hackerone" in req.url.path else [])

    from crawler import db

    c = BountyTargetsCollector(config.get_settings(), fetcher=_fetcher(handler))
    c.enabled = lambda: True
    s = db.get_sessionmaker()()
    discover(s, [c], progress=lambda m, transient=False: seen.append((m, transient)))
    s.rollback()
    assert ("Reading bounty_targets...", False) in seen
    assert ("  bounty listings 1/5: hackerone", True) in seen
