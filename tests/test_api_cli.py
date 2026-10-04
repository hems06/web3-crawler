from click.testing import CliRunner
from fastapi.testclient import TestClient

from crawler.api.app import app
from crawler.cli import main


def test_api_has_no_way_to_bypass_the_gate(discovered):
    paths = {r.path for r in app.routes}
    assert not any("research-mode" in p or "bypass" in p or "/research/start" in p for p in paths)
    c = TestClient(app)
    assert c.get("/api/settings").json()["research_mode"] is False
    progs = c.get("/api/programs").json()
    assert [p["name"] for p in progs] == ["Example Protocol"]
    assert progs[0]["indicator"]["label"] == "NOT AUTHORIZED"
    d = c.post("/api/gate/check", json={"asset": "api.example.com", "method": "static_analysis"}).json()
    assert d["action"] == "BLOCKED" and d["reason"] == "SCOPE_UNKNOWN"
    assert c.get("/api/blocked").json()[0]["asset"] == "api.example.com"


def test_api_authorization_flow(discovered):
    c = TestClient(app)
    pid = c.get("/api/programs").json()[0]["id"]
    draft = c.post(f"/api/programs/{pid}/authorization-request", json={}).json()
    assert draft["status"] == "DRAFT"
    assert c.post(f"/api/requests/{draft['id']}/mark-sent").json()["status"] == "SENT"
    r = c.post(f"/api/programs/{pid}/responses", json={"body": "We appreciate security researchers!"}).json()
    assert r["classifications"] == ["UNKNOWN"]
    auth = c.get("/api/authorization").json()
    assert auth[0]["indicator"]["label"] == "WAITING FOR RESPONSE"
    assert c.get("/api/research-ready").json()["programs"] == []


def test_cli_private_output(discovered):
    out = CliRunner().invoke(main, ["private", "--exclude", "immunefi"]).output
    assert "[PRIVATE] Example Protocol" in out
    assert "Authorization: REQUIRED" in out
    assert "Status: WAITING_FOR_AUTHORIZATION" in out


def test_cli_generate_does_not_send(discovered, set_env):
    res = CliRunner().invoke(main, ["authorize", "generate", "Example Protocol"])
    assert res.exit_code == 0, res.output
    assert "Not sent." in res.output
    set_env(EMAIL_PROVIDER="none")
    res = CliRunner().invoke(main, ["authorize", "send", "1"])
    assert res.exit_code != 0 and "EMAIL_PROVIDER=none" in res.output


def test_cli_research_check_blocks(discovered):
    res = CliRunner().invoke(main, ["research", "check", "app.example.com", "--program", "Example Protocol"])
    assert res.exit_code == 2 and "BLOCKED" in res.output


def test_bare_crawler_runs_default(discovered):
    res = CliRunner().invoke(main, ["--help"])
    assert "run" in res.output
    res = CliRunner().invoke(main, [])
    assert res.exit_code == 0, res.output
    assert "[PRIVATE] Example Protocol" in res.output
    assert "Next: crawler authorize generate" in res.output
    assert "nothing is tested automatically" in res.output
    assert "Discovery:" in res.output


def test_run_without_discovery(discovered):
    res = CliRunner().invoke(main, ["run", "--no-discover"])
    assert res.exit_code == 0, res.output
    assert "Discovery:" not in res.output and "Example Protocol" in res.output
