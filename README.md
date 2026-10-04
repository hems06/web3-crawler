# Web3 Crawler

An authorization-first crawler for Web3 bug bounty programs. It finds
private and invite-only programs from legitimate sources, drafts an
authorization request for each one, tracks the reply, confirms scope and
bounty terms, and blocks every research action until those gates pass.

It optimizes for:

> find legitimate private Web3 security opportunities → obtain explicit
> authorization → confirm scope → confirm bounty terms → then perform
> authorized research.

It does not scan, exploit or brute-force anything. Discovery is passive.
Vulnerability testing is a separate module that cannot run until the
authorization gate allows it, and `RESEARCH_MODE` is `false` by default.

## Installation

One command (needs Python 3.11+ and git):

```bash
curl -fsSL https://raw.githubusercontent.com/hems06/web3-crawler/main/install.sh | bash
```

From a clone, run `./install.sh` instead. The script creates a virtual
environment in `~/.web3-crawler`, installs the package, creates `.env` from
`.env.example` with the database in `~/.web3-crawler/data`, and links
`crawler` into `~/.local/bin`. Running it again updates an existing install.

| Variable | Default | Meaning |
|---|---|---|
| `WEB3_CRAWLER_HOME` | `~/.web3-crawler` | install directory |
| `WEB3_CRAWLER_REF` | `main` | branch or tag to install |
| `WEB3_CRAWLER_BIN` | `~/.local/bin` | where `crawler` is linked |
| `WITH_DASHBOARD=1` | off | also install dashboard dependencies (Node 20+) |
| `WITH_KEYRING=1` | off | keep the SMTP password in the OS keyring |

For example: `curl -fsSL .../install.sh | WITH_DASHBOARD=1 WITH_KEYRING=1 bash`.

For a manual install, use `pip install -e ".[dev]"` and `cp .env.example .env`.
Docker is also an option: `docker compose up --build`.

## Quick start

```bash
crawler                       # discover, then list private candidates and next steps
crawler private --exclude immunefi
crawler authorize generate "Example Protocol"
```

Then send the draft yourself and record it:

```bash
crawler authorize mark-sent 1
crawler verify response "Example Protocol" --file reply.txt --sender sec@example.com
crawler verify apply 1        # shows the parsed result, asks before applying
crawler research-ready
```

Dashboard and API:

```bash
crawler serve                       # API on :8000
cd dashboard && npm install && npm run dev   # dashboard on :5173
```

Or everything in Docker: `docker compose up --build` (dashboard on :3000).

## Pipeline

```
Collectors → Normalizer → Program Classifier → Private Program Filter
→ Authorization Manager → Scope Engine → Asset Intelligence
→ Authorization Gate → Research Queue
```

| Stage | Code |
|---|---|
| Collectors | `crawler/collectors/` — seed YAML, RFC 9116 `security.txt`, public program pages, HackerOne Hacker API |
| Normalizer | `crawler/normalizer.py` |
| Classifier | `crawler/classifier.py` — `PRIVATE_CONFIRMED`, `PRIVATE_POSSIBLE`, `PUBLIC`, `VDP_ONLY`, `UNKNOWN` |
| Filter | `crawler/filters.py` + `config/platforms.yaml` |
| Authorization manager | `crawler/authorization/` — email generator, state machine, response parser, optional SMTP/IMAP |
| Scope engine | `crawler/scope/engine.py` |
| Asset intelligence | `crawler/assets/` — scope inventory, CT-log subdomains, Sourcify/Etherscan contract metadata |
| Gate | `crawler/gate.py` — `check_authorization()` |
| Research | `crawler/research/runner.py` — gated Slither static analysis only |
| Scoring | `crawler/scoring.py` + `config/scoring.yaml` |
| Audit / notifications | `crawler/audit.py`, `crawler/notifications.py` |
| API / CLI / workers | `crawler/api/app.py`, `crawler/cli.py`, `crawler/workers/` |
| Dashboard | `dashboard/` (React + Vite) |

Collectors read only public pages and official APIs you hold credentials
for. The fetcher honours `robots.txt`, identifies itself, rate limits per
host, fetches HTTPS only, and stops at any login wall (401/403).

## Private program classification

`PRIVATE_CONFIRMED` needs the source itself to acknowledge the program
(for example a HackerOne program you were invited to, or a seed entry with
`private_acknowledged: true`). Wording such as "invite-only", "apply to
join", "contact our security team for access", or a project that is only
reachable through `security.txt` gives `PRIVATE_POSSIBLE`. Neither one is
authorization: an unlisted or hidden program is a reason to ask, never a
reason to test.

## Platform filtering

`config/platforms.yaml` holds `excluded_platforms`,
`excluded_program_types` and per-platform defaults for four access
properties:

- `platform_reputation_required`
- `invite_required`
- `application_required`
- `private_program_supported`

Each program stores its own copy of those properties (platform default,
overridden by evidence the collector found for that program). Program types
such as `reputation_based` are defined in `program_type_definitions` as a
combination of those properties, so excluding `reputation_based` drops
programs whose access is gated on reputation, not every platform that
happens to show a leaderboard. Add platforms or types by editing the YAML;
`PLATFORM_EXCLUSIONS` and `--exclude` add more at runtime. The CLI exposes
each property as a filter, e.g. `crawler programs --no-invite-required`.

## Authorization state machine

```
DISCOVERED → PRIVATE_CANDIDATE → AUTHORIZATION_REQUESTED → AWAITING_RESPONSE
→ AUTHORIZED → SCOPE_CONFIRMED → BOUNTY_CONFIRMED → READY_FOR_RESEARCH
```

Negative states: `NOT_AUTHORIZED`, `DECLINED`, `NO_RESPONSE`, `VDP_ONLY`,
`BOUNTY_NOT_AVAILABLE`, `SCOPE_UNCLEAR`, `EXPIRED_AUTHORIZATION`.
Transitions are validated in `crawler/authorization/state_machine.py` and
every one is written to the audit log. `READY_FOR_RESEARCH` requires
recorded authorization evidence, confirmed scope and, when
`REQUIRE_BOUNTY_CONFIRMATION=true`, confirmed bounty terms.

## Authorization emails

`crawler authorize generate` drafts the request email (subject
"Security Research / Bug Bounty Authorization Request — <Project>") with the
eight questions about reports, testing permission, program status, rewards,
scope, prohibited techniques, written authorization and preferred contact.
Drafts are never sent without your approval. To send one by email, run
`crawler authorize send <id>` (or `--all`). The first time, it asks for your
SMTP host, security (STARTTLS or SSL), port, username, password and from
address, and asks once whether emails may be sent without asking each time.
It tests the login and saves the answers, so you aren't asked again.

With that standing approval on, `crawler authorize generate` sends the
email right away and `authorize send` doesn't prompt. That only happens when:
- the recipient is the program's published security contact,
- no earlier request to that program was sent, and
- fewer than `AUTO_SEND_MAX_PER_HOUR` (default 10) emails went out in the
  last hour.

Any other email is shown and needs your confirmation. Every send is in the
audit log, and approvals given this way are recorded with the actor
`standing approval (auto_send)`. To turn the standing approval off, run
`crawler email setup` again or `crawler email forget`; `--no-send` drafts
without sending.

The settings are saved outside the repository and the database, in
`~/.config/web3-crawler/smtp.json` (directory 0700, file 0600). The password
goes to the OS keyring when `pip install ".[keyring]"` is installed and a
keyring backend is available; otherwise it stays in that 0600 file.
`SMTP_*` environment variables override the saved file, and
`EMAIL_PROVIDER=none` turns sending off entirely. To manage the settings, use
`crawler email setup | show | test | forget`. If you would rather send from
your own mail client, do that and run `crawler authorize mark-sent <id>`.

## Response parser

`crawler/authorization/response_parser.py` classifies replies as
`AUTHORIZED`, `PARTIALLY_AUTHORIZED`, `NOT_AUTHORIZED`, `BOUNTY_CONFIRMED`,
`BOUNTY_NOT_AVAILABLE`, `SCOPE_CONFIRMED`, `SCOPE_REQUIRES_CLARIFICATION` or
`UNKNOWN`, and extracts domains, contract addresses, GitHub repositories,
APIs, chains, restrictions, bounty amounts, severity lines, expiry dates,
contacts and the submission method. It is conservative: friendly but vague
replies ("feel free to look around", "we appreciate security researchers")
classify as `UNKNOWN`, grants need an explicit sentence without negation,
conditions such as an NDA give `PARTIALLY_AUTHORIZED`, quoted history is
ignored, and scope is confirmed only when concrete assets are named. A
parsed reply changes nothing until you apply it (`crawler verify apply` or
the dashboard's "Apply after review"). The optional IMAP poller records
replies the same way and never applies them.

## Scope engine

Scope rules come from the program listing (stored, but *not* confirmed),
from applied replies, or from `crawler scope import <program> scope.yaml`:

```yaml
scope:
  domains: [example.com, "*.app.example.com"]
  contracts: ["0x...", {address: "0x...", chain: Arbitrum}]
  repositories: [github.com/example/project]
  chains: [Ethereum, Arbitrum]
  out_of_scope: [third_party_services, production_users, social_engineering, denial_of_service]
```

Every asset is evaluated as `IN_SCOPE`, `OUT_OF_SCOPE` or `SCOPE_UNKNOWN`.
Out-of-scope rules win; subdomains need an explicit wildcard; a contract
rule with a chain matches only that chain. With `REQUIRE_EXPLICIT_SCOPE=true`
only confirmed rules count. Out-of-scope categories such as
`denial_of_service` become prohibited methods for the gate.

## Safety gate

Every research action calls `check_authorization(asset, method)`, which
checks that:

1. the program exists,
2. authorization is recorded with evidence,
3. it has not expired,
4. the asset is inside confirmed scope,
5. the method is permitted (exploitation, brute force, credential attacks,
   DoS, phishing, social engineering and auth bypass are always blocked;
   only non-live methods are allowed by default; program restrictions add
   more),
6. `RESEARCH_MODE=true` in the server environment.

Any failure blocks the action and records an `AuthorizationBlockedEvent`
(`research_blocked` in the audit log, plus a `BLOCKED` research session):

```json
{"asset": "api.example.com", "reason": "SCOPE_UNKNOWN", "timestamp": "...", "action": "BLOCKED"}
```

Blocked events are committed before the exception is raised, so a caller's
rollback cannot erase them. The gate reads `RESEARCH_MODE` from the
environment only; the API has no endpoint that changes it, starts research
or marks a program authorized without evidence. Celery research jobs go to a
separate `research` queue that the default worker does not consume, and the
gate is re-checked inside the worker.

## Opportunity score

`config/scoring.yaml` weights `authorization_status`, `scope_clarity`,
`bounty_available`, `max_bounty`, `program_freshness`, `asset_quality`,
`smart_contract_availability`, `scope_size` and `competition_level`.
Researcher reputation, submission counts, leaderboards, popularity and
historical payouts are not inputs.

## Audit log and notifications

`audit_events` is append-only: database triggers reject `UPDATE` and
`DELETE` (SQLite and Postgres) and each row is hash-chained to the previous
one. `crawler audit --verify-chain` checks the chain. Logged events include
`program_discovered`, `program_classified`, `authorization_email_generated`,
`authorization_email_sent`, `authorization_response_received`,
`scope_updated`, `bounty_confirmed`, `asset_discovered`, `research_started`,
`research_blocked` and `finding_created`.

Notifications (stored, logged, optionally posted to `NOTIFY_WEBHOOK_URL`)
fire when a private program is discovered, an authorization email is
ready, a reply arrives, authorization or scope or bounty is confirmed, and
when authorization expires. Notifications never trigger testing.

## Configuration

See `.env.example`. Key settings:

| Variable | Default | Meaning |
|---|---|---|
| `PLATFORM_EXCLUSIONS` | `immunefi` | extra platforms to skip |
| `PROGRAM_TYPE_FILTER` | empty | classifications to keep |
| `MIN_BOUNTY` | `0` | minimum listed bounty (private programs with unknown bounty are kept) |
| `PRIVATE_ONLY` | `true` | default listing shows private candidates only |
| `REQUIRE_BOUNTY_CONFIRMATION` | `true` | bounty must be confirmed before research |
| `REQUIRE_EXPLICIT_SCOPE` | `true` | only confirmed scope counts |
| `AUTHORIZATION_EXPIRY` | `90` | days, when a reply gives no expiry |
| `RESEARCH_MODE` | `false` | master switch for research actions |
| `EMAIL_PROVIDER` | empty | empty = use saved SMTP settings if any; `none` = never send; `smtp` = send |

SQLite is the default database; the schema is portable to Postgres
(`pip install ".[postgres]"` and set `DATABASE_URL`).

## CLI

```
crawler                       # default: same as `crawler run`
crawler run [--no-discover] [--exclude P]   # passive discovery + private candidates with next steps
crawler discover [--collector NAME] [--seed FILE] [--exclude PLATFORM]
crawler programs | private [--exclude P] [--classification C] [--min-bounty N] [--[no-]invite-required ...] [--json]
crawler authorize generate|list|show|approve|send|mark-sent
crawler email setup|show|test|forget
crawler verify response|apply|confirm|bounty|expire|inbox
crawler scope show|import|check
crawler assets PROGRAM [--passive]
crawler research-ready
crawler blocked
crawler report [--format md|json]
crawler audit [--verify-chain]
crawler research check|static      # gated module
```

## Tests

```bash
pytest -q
```

The suite covers the parser's handling of vague and negated replies, the
scope engine, every gate condition, the state machine, the append-only audit
log, platform/program-type filtering, and the full discovery → email → reply
→ gate flow through the CLI and API.
