import pytest

from crawler import config, db


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # keep any stray .env out of the tests
    url = f"sqlite:///{tmp_path}/test.db"
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("RESEARCH_MODE", "false")
    monkeypatch.setenv("REQUIRE_BOUNTY_CONFIRMATION", "true")
    monkeypatch.setenv("REQUIRE_EXPLICIT_SCOPE", "true")
    monkeypatch.setenv("PLATFORM_EXCLUSIONS", "")
    monkeypatch.setenv("PRIVATE_ONLY", "true")
    monkeypatch.setenv("REQUEST_DELAY_SECONDS", "0")
    monkeypatch.setenv("SMTP_CONFIG_FILE", str(tmp_path / "smtpconf" / "smtp.json"))
    for var in ("EMAIL_PROVIDER", "SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM"):
        monkeypatch.delenv(var, raising=False)
    # Never touch a real OS keyring from tests.
    from crawler.authorization import smtp_service

    monkeypatch.setattr(smtp_service, "_keyring", lambda: None)
    config.get_settings.cache_clear()
    db.configure(url)
    yield
    config.get_settings.cache_clear()


@pytest.fixture
def session():
    s = db.get_sessionmaker()()
    yield s
    s.rollback()
    s.close()


@pytest.fixture
def set_env(monkeypatch):
    def _set(**kwargs):
        for k, v in kwargs.items():
            monkeypatch.setenv(k, str(v))
        config.get_settings.cache_clear()
        return config.get_settings()

    return _set


SEED = {
    "name": "Example Protocol",
    "project_name": "Example Labs",
    "platform": "direct",
    "program_url": "https://example.com/security",
    "program_type": "private",
    "listed_scope": [
        {"type": "domain", "value": "app.example.com"},
        {"type": "contract", "value": "0x00000000000000000000000000000000000000aa", "chain": "Ethereum"},
    ],
    "listed_out_of_scope": ["third_party_services", "denial_of_service"],
    "max_bounty": "$50,000",
    "security_email": "security@example.com",
    "notes": "Invite-only program. Contact the security team for access.",
}


class ListCollector:
    name = "test"

    def __init__(self, items):
        self.items = items

    def enabled(self):
        return True

    def collect(self):
        return list(self.items)


@pytest.fixture
def discovered(session):
    """Run discovery with a single private program plus noise."""
    from crawler.pipeline import discover

    items = [
        SEED,
        {"name": "Immunefi Thing", "platform": "immunefi", "program_url": "https://immunefi.com/x", "program_type": "public", "max_bounty": "$1M"},
        {"name": "Open DEX", "platform": "hackenproof", "program_url": "https://hackenproof.com/dex", "program_type": "public", "max_bounty": "$10,000"},
        {"name": "Invite H1", "platform": "hackerone", "program_url": "https://hackerone.com/inv", "program_type": "private", "private_acknowledged": True},
    ]
    result = discover(session, [ListCollector(items)])
    session.commit()
    return result


AUTH_REPLY = """Hi,

Thanks for reaching out. You are authorized to test the assets below until 2099-12-31.

In scope:
- app.example.com
- 0x00000000000000000000000000000000000000aa on Ethereum
- https://github.com/example/contracts

Out of scope:
- legacy.example.com

Restrictions:
- Do not perform denial of service or load testing.
- Do not test on mainnet; use a local fork.

Valid findings are eligible for a bounty of up to $50,000 USDC, critical up to $50,000, high up to $10,000.
Please submit reports via security@example.com.

> On Mon someone wrote:
> you are authorized to test everything
"""
