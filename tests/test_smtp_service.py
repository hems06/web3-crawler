import json
import stat

from click.testing import CliRunner
from sqlalchemy import select

from crawler import config
from crawler.authorization import smtp_service
from crawler.cli import main
from crawler.enums import AuthState, RequestStatus
from crawler.models import AuthorizationRequest, Program


class FakeSMTP:
    sent = []
    logins = []

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def send_message(self, msg):
        FakeSMTP.sent.append(msg)


def fake_connect(cfg):
    FakeSMTP.logins.append((cfg.host, cfg.username, cfg.password))
    return FakeSMTP()


def test_save_and_load_roundtrip_with_private_file():
    s = config.get_settings()
    cfg = smtp_service.SmtpConfig(host="smtp.example.com", port=465, security="ssl", username="me@example.com", from_addr="me@example.com", password="pw")
    path = smtp_service.save(cfg, s)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert smtp_service.load(s) == cfg
    assert smtp_service.effective_provider(s) == "smtp"
    assert smtp_service.forget(s) and smtp_service.load(s) is None
    assert smtp_service.effective_provider(s) == "none"


def test_password_goes_to_keyring_when_available(monkeypatch):
    store = {}

    class KR:
        def set_password(self, svc, user, pw):
            store[(svc, user)] = pw

        def get_password(self, svc, user):
            return store.get((svc, user))

    monkeypatch.setattr(smtp_service, "_keyring", lambda: KR())
    s = config.get_settings()
    path = smtp_service.save(smtp_service.SmtpConfig(host="h", username="u", password="secret"), s)
    assert "secret" not in path.read_text()
    assert json.loads(path.read_text())["password_in_keyring"] is True
    assert smtp_service.load(s).password == "secret"


def test_env_overrides_saved_file(set_env):
    smtp_service.save(smtp_service.SmtpConfig(host="saved.example.com"), config.get_settings())
    s = set_env(SMTP_HOST="env.example.com", SMTP_PORT="2525")
    assert smtp_service.load(s).host == "env.example.com"


def test_first_send_asks_once_then_remembers(session, discovered, monkeypatch):
    monkeypatch.setattr(smtp_service, "_connect", fake_connect)
    FakeSMTP.sent.clear()
    runner = CliRunner()
    assert runner.invoke(main, ["authorize", "generate", "Example Protocol"]).exit_code == 0
    # host, security, port, username, password, from, confirm send
    answers = "smtp.example.com\nstarttls\n587\nme@example.com\napppw\n\ny\n"
    res = runner.invoke(main, ["authorize", "send", "1"], input=answers)
    assert res.exit_code == 0, res.output
    assert "You won't be asked again" in res.output
    assert len(FakeSMTP.sent) == 1 and FakeSMTP.sent[0]["To"] == "security@example.com"
    assert FakeSMTP.sent[0]["From"] == "me@example.com"

    # Second request: no SMTP questions, only the per-email confirmation.
    assert runner.invoke(main, ["authorize", "generate", "Example Protocol"]).exit_code == 0
    res = runner.invoke(main, ["authorize", "send", "2"], input="y\n")
    assert res.exit_code == 0, res.output
    assert "SMTP host" not in res.output and len(FakeSMTP.sent) == 2
    session.expire_all()
    assert session.get(AuthorizationRequest, 2).status == RequestStatus.SENT
    p = session.scalars(select(Program).where(Program.name == "Example Protocol")).one()
    assert p.authorization_status == AuthState.AWAITING_RESPONSE


def test_declining_the_preview_sends_nothing(session, discovered, monkeypatch):
    monkeypatch.setattr(smtp_service, "_connect", fake_connect)
    smtp_service.save(smtp_service.SmtpConfig(host="smtp.example.com"), config.get_settings())
    FakeSMTP.sent.clear()
    runner = CliRunner()
    runner.invoke(main, ["authorize", "generate", "Example Protocol"])
    res = runner.invoke(main, ["authorize", "send", "1"], input="n\n")
    assert res.exit_code != 0 and FakeSMTP.sent == []
    session.expire_all()
    assert session.get(AuthorizationRequest, 1).status == RequestStatus.DRAFT
    # --yes cannot skip review of an unapproved draft
    res = runner.invoke(main, ["authorize", "send", "1", "--yes"])
    assert res.exit_code != 0 and "needs an approved request" in res.output and FakeSMTP.sent == []
