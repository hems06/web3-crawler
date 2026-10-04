"""`crawler` command line interface."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import click
import yaml
from sqlalchemy import select

from . import audit, reporting, status
from .assets import intelligence
from .authorization import manager
from .authorization.response_parser import ParsedResponse
from .classifier import PRIORITY
from .collectors import REGISTRY
from .collectors.seed import SeedCollector
from .config import PlatformConfig, get_settings
from .db import session_scope
from .enums import AuditEventType, AuthState, ResearchMethod
from .filters import ProgramFilter
from .gate import AuthorizationBlocked, check_authorization
from .models import AuditEvent, AuthorizationRequest, AuthorizationResponse, Program, ResearchSession
from .pipeline import discover as run_discovery
from .research import runner
from .scope import engine as scope_engine


def _program(session, ref: str) -> Program:
    program = session.get(Program, int(ref)) if ref.isdigit() else session.scalars(
        select(Program).where(Program.name.ilike(ref))
    ).first()
    if program is None:
        raise click.ClickException(f"no program matches {ref!r}")
    return program


def _get(session, model, ident: int):
    obj = session.get(model, ident)
    if obj is None:
        raise click.ClickException(f"{model.__name__} #{ident} not found")
    return obj


def _print_program(p: Program, label: str | None = None) -> None:
    icon, text = status.indicator(p)
    tag = label or p.classification
    click.echo(f"[{tag}] {p.name}  (#{p.id}, {p.platform.slug}, score {p.opportunity_score})")
    click.echo(f"  Authorization: {status.authorization_label(p)}")
    click.echo(f"  Bounty: {p.bounty_status}" + (f" (max {p.max_bounty:,.0f} {p.bounty_currency or ''})" if p.max_bounty else ""))
    click.echo(f"  Scope: {p.scope_status}")
    click.echo(f"  Status: {status.workflow_status(p)}  {icon} {text}")


def _list(session, flt: ProgramFilter) -> list[Program]:
    pc = PlatformConfig.load()
    programs = flt.apply(session.scalars(select(Program)).all(), pc)
    return sorted(programs, key=lambda p: (PRIORITY.get(p.classification, 9), -p.opportunity_score))


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx):
    """Authorization-first Web3 bug bounty crawler.

    With no command, runs `crawler run`: passive discovery, then the private
    candidates and what each one needs next. It never starts research.
    """
    if ctx.invoked_subcommand is None:
        ctx.invoke(run)


@main.command()
@click.option("--collector", "collectors", multiple=True, type=click.Choice(sorted(REGISTRY)), help="Run only these collectors.")
@click.option("--seed", "seeds", multiple=True, type=click.Path(exists=True, path_type=Path), help="Extra seed YAML file.")
@click.option("--exclude", multiple=True, help="Skip this platform (adds to config/platforms.yaml).")
def discover(collectors, seeds, exclude):
    """Collect programs from configured legitimate sources (passive)."""
    settings = get_settings()
    chosen = [REGISTRY[c](settings) for c in (collectors or REGISTRY)]
    if seeds:
        chosen = [c for c in chosen if c.name != "seed"] + [SeedCollector(settings, paths=list(seeds))]
    with session_scope() as s:
        result = run_discovery(s, chosen, settings, extra_exclusions=list(exclude))
    click.echo(f"new: {len(result.new)}  updated: {len(result.updated)}  skipped: {len(result.skipped)}")
    for line in result.skipped:
        click.echo(f"  skipped {line}")
    for err in result.errors:
        click.echo(f"  error {err}", err=True)


NEXT_STEP = {
    AuthState.DISCOVERED: "crawler authorize generate {id}",
    AuthState.PRIVATE_CANDIDATE: "crawler authorize generate {id}",
    AuthState.AUTHORIZATION_REQUESTED: "review the draft, send it, then crawler authorize mark-sent",
    AuthState.AWAITING_RESPONSE: "wait for a reply, then crawler verify response {id}",
    AuthState.AUTHORIZED: "ask the program to confirm scope",
    AuthState.SCOPE_UNCLEAR: "ask the program to confirm scope",
    AuthState.SCOPE_CONFIRMED: "ask the program to confirm bounty terms",
    AuthState.NO_RESPONSE: "follow up, or crawler authorize generate {id}",
    AuthState.EXPIRED_AUTHORIZATION: "request renewed authorization: crawler authorize generate {id}",
}


@main.command()
@click.option("--no-discover", is_flag=True, help="Skip discovery and only show the current state.")
@click.option("--exclude", multiple=True, help="Skip this platform.")
def run(no_discover, exclude):
    """Default command: discover passively, then list private candidates.

    Steps: run every enabled collector, expire stale authorizations, then show
    private candidates by priority with the next authorization step for each.
    """
    settings = get_settings()
    with session_scope() as s:
        if not no_discover:
            result = run_discovery(s, [cls(settings) for cls in REGISTRY.values()], settings, extra_exclusions=list(exclude))
            click.echo(f"Discovery: {len(result.new)} new, {len(result.updated)} updated, {len(result.skipped)} skipped")
            for err in result.errors:
                click.echo(f"  error {err}", err=True)
        for p in manager.expire_authorizations(s):
            click.echo(f"Authorization expired: {p.name}")
        flt = ProgramFilter.from_settings(extra_exclusions=list(exclude))
        flt.private_only = True
        candidates = _list(s, flt)
        click.echo(f"\n{len(candidates)} private candidate(s)\n")
        for p in candidates:
            _print_program(p, "PRIVATE")
            step = NEXT_STEP.get(AuthState(p.authorization_status))
            if step:
                click.echo(f"  Next: {step.format(id=p.id)}")
            click.echo()
        pending = s.scalars(select(AuthorizationResponse).where(AuthorizationResponse.applied_at.is_(None))).all()
        if pending:
            click.echo(f"{len(pending)} reply(ies) waiting for review: " + ", ".join(f"crawler verify apply {r.id}" for r in pending))
        ready = s.scalars(select(Program).where(Program.authorization_status == AuthState.READY_FOR_RESEARCH)).all()
        click.echo(f"{len(ready)} program(s) research-ready. Research mode is {'ON' if settings.research_mode else 'OFF'}; "
                   "nothing is tested automatically.")


def _filter_opts(f):
    f = click.option("--exclude", multiple=True, help="Exclude a platform.")(f)
    f = click.option("--classification", multiple=True, help="Keep only these classifications.")(f)
    f = click.option("--min-bounty", type=float, default=None)(f)
    for key in PlatformConfig.ACCESS_KEYS:
        f = click.option(f"--{key.replace('_', '-')}/--no-{key.replace('_', '-')}", key, default=None)(f)
    f = click.option("--json", "as_json", is_flag=True)(f)
    return f


def _emit(programs, as_json, label=None):
    if as_json:
        click.echo(json.dumps([reporting.program_dict(p) for p in programs], indent=2, default=str))
        return
    if not programs:
        click.echo("no programs match")
    for p in programs:
        _print_program(p, label)
        click.echo()


@main.command()
@_filter_opts
def programs(exclude, classification, min_bounty, as_json, **access):
    """List programs (all classifications)."""
    with session_scope() as s:
        flt = ProgramFilter.from_settings(
            extra_exclusions=list(exclude), private_only=False,
            classifications={c.upper() for c in classification} or None, min_bounty=min_bounty, **access,
        )
        _emit(_list(s, flt), as_json)


@main.command()
@_filter_opts
def private(exclude, classification, min_bounty, as_json, **access):
    """List private / invite-only candidates, highest priority first."""
    with session_scope() as s:
        flt = ProgramFilter.from_settings(
            extra_exclusions=list(exclude), classifications={c.upper() for c in classification} or None,
            min_bounty=min_bounty, **access,
        )
        flt.private_only = True
        _emit(_list(s, flt), as_json, label="PRIVATE")


# ---------------------------------------------------------------- authorize
@main.group()
def authorize():
    """Draft, approve and send authorization requests."""


@authorize.command("generate")
@click.argument("program")
@click.option("--to", "recipient", help="Recipient (defaults to the program's public security email).")
def authorize_generate(program, recipient):
    """Draft an authorization request email. Nothing is sent."""
    with session_scope() as s:
        req = manager.generate_request(s, _program(s, program), recipient)
        click.echo(f"Draft #{req.id} to {req.recipient or '(no recipient yet)'}\n")
        click.echo(f"Subject: {req.subject}\n\n{req.body}")
        click.echo("Not sent. Approve with `crawler authorize approve %d`, or send it yourself and run "
                   "`crawler authorize mark-sent %d`." % (req.id, req.id))


@authorize.command("list")
def authorize_list():
    with session_scope() as s:
        for r in s.scalars(select(AuthorizationRequest).order_by(AuthorizationRequest.id)):
            click.echo(f"#{r.id} {r.status:9} {r.program.name} -> {r.recipient or '-'}  sent={r.sent_at or '-'}")


@authorize.command("show")
@click.argument("request_id", type=int)
def authorize_show(request_id):
    with session_scope() as s:
        r = _get(s, AuthorizationRequest, request_id)
        click.echo(f"#{r.id} {r.status} to {r.recipient}\nSubject: {r.subject}\n\n{r.body}")


@authorize.command("approve")
@click.argument("request_id", type=int)
@click.option("--to", "recipient", help="Set or change the recipient before approving.")
def authorize_approve(request_id, recipient):
    """Approve a draft for sending through the configured provider."""
    with session_scope() as s:
        r = _get(s, AuthorizationRequest, request_id)
        if recipient:
            r.recipient = recipient
        manager.approve_request(s, r)
        click.echo(f"#{r.id} approved for {r.recipient}. Send with `crawler authorize send {r.id}`.")


@authorize.command("send")
@click.argument("request_id", type=int)
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def authorize_send(request_id, yes):
    """Send an approved request (needs EMAIL_PROVIDER=smtp)."""
    settings = get_settings()
    if settings.email_provider == "none":
        raise click.ClickException("EMAIL_PROVIDER=none: send the draft yourself, then run `crawler authorize mark-sent`.")
    with session_scope() as s:
        r = _get(s, AuthorizationRequest, request_id)
        if not yes:
            click.echo(f"To: {r.recipient}\nSubject: {r.subject}\n\n{r.body}")
            click.confirm("Send this email now?", abort=True)
        manager.send_request(s, r, settings)
        click.echo(f"#{r.id} sent to {r.recipient}.")


@authorize.command("mark-sent")
@click.argument("request_id", type=int)
def authorize_mark_sent(request_id):
    """Record that you sent the draft from your own mail client."""
    with session_scope() as s:
        r = _get(s, AuthorizationRequest, request_id)
        manager.mark_sent_manually(s, r)
        click.echo(f"#{r.id} marked sent; {r.program.name} is now AWAITING_RESPONSE.")


# ------------------------------------------------------------------- verify
@main.group()
def verify():
    """Record replies and verify authorization, scope and bounty terms."""


@verify.command("response")
@click.argument("program")
@click.option("--file", "path", type=click.File(), default="-", help="Reply body (default: stdin).")
@click.option("--sender")
@click.option("--subject")
def verify_response(program, path, sender, subject):
    """Store and classify a reply. It is not applied until you review it."""
    body = path.read()
    with session_scope() as s:
        resp = manager.record_response(s, _program(s, program), body, sender, subject)
        _show_response(resp)
        click.echo(f"\nReview, then apply with `crawler verify apply {resp.id}`.")


def _show_response(resp: AuthorizationResponse) -> None:
    p = ParsedResponse(**resp.extracted)
    click.echo(f"Response #{resp.id}: {', '.join(p.classifications)}")
    for label, values in (
        ("domains", p.domains), ("contracts", p.contracts), ("repositories", p.repositories), ("apis", p.apis),
        ("chains", p.chains), ("out of scope", p.out_of_scope), ("restrictions", p.restrictions),
        ("prohibited methods", p.prohibited_methods), ("bounty amounts", p.bounty_amounts),
        ("severity", p.severity_definitions), ("contacts", p.security_contacts),
    ):
        if values:
            click.echo(f"  {label}: {', '.join(values)}")
    if p.expiration:
        click.echo(f"  expires: {p.expiration}")
    if p.submission_method:
        click.echo(f"  submission: {p.submission_method}")
    for e in p.evidence:
        click.echo(f"  evidence: \"{e}\"")


@verify.command("apply")
@click.argument("response_id", type=int)
@click.option("--yes", is_flag=True)
def verify_apply(response_id, yes):
    """Apply a reviewed reply to the program's authorization state."""
    with session_scope() as s:
        resp = _get(s, AuthorizationResponse, response_id)
        _show_response(resp)
        if not yes:
            click.confirm("Apply this classification?", abort=True)
        changes = manager.apply_response(s, resp)
        program = s.get(Program, resp.program_id)
        click.echo(f"applied: {', '.join(changes)}\nstate: {program.authorization_status}")
        missing = manager.gates_satisfied(program, get_settings())
        click.echo("research gates: " + ("satisfied" if not missing else "missing " + ", ".join(missing)))


@verify.command("confirm")
@click.argument("program")
@click.option("--evidence", required=True, help="Link, quote or document proving written authorization.")
@click.option("--expires", type=click.DateTime(["%Y-%m-%d"]))
def verify_confirm(program, evidence, expires):
    """Record authorization you received outside this tool."""
    with session_scope() as s:
        p = _program(s, program)
        exp = expires.replace(tzinfo=timezone.utc) if expires else None
        manager.confirm_authorization_manually(s, p, evidence, exp)
        click.echo(f"{p.name}: {p.authorization_status} until {p.authorization_expires_at:%Y-%m-%d}")


@verify.command("bounty")
@click.argument("program")
@click.option("--available/--not-available", required=True)
@click.option("--max", "max_bounty", type=float)
@click.option("--currency", default="USD")
@click.option("--evidence", required=True)
def verify_bounty(program, available, max_bounty, currency, evidence):
    """Record bounty terms the program confirmed to you."""
    with session_scope() as s:
        p = _program(s, program)
        manager.confirm_bounty_manually(s, p, available, max_bounty, currency, evidence)
        click.echo(f"{p.name}: bounty {p.bounty_status}, state {p.authorization_status}")


@verify.command("expire")
@click.option("--no-response-days", default=30, show_default=True)
def verify_expire(no_response_days):
    """Expire stale authorizations and flag requests with no reply."""
    with session_scope() as s:
        for p in manager.expire_authorizations(s):
            click.echo(f"expired: {p.name}")
        for p in manager.mark_no_response(s, no_response_days):
            click.echo(f"no response: {p.name}")


@verify.command("inbox")
def verify_inbox():
    """Read unseen replies from the configured IMAP inbox (read-only)."""
    from .workers.tasks import poll_inbox

    click.echo(f"recorded {poll_inbox()} responses")


# -------------------------------------------------------------------- scope
@main.group()
def scope():
    """Show, confirm and check program scope."""


@scope.command("show")
@click.argument("program")
def scope_show(program):
    with session_scope() as s:
        p = _program(s, program)
        click.echo(f"{p.name}: scope {p.scope_status}")
        for r in sorted(p.scope_rules, key=lambda r: (not r.in_scope, r.rule_type, r.value)):
            mark = "IN " if r.in_scope else "OUT"
            conf = "confirmed" if r.confirmed else "listed only"
            click.echo(f"  {mark} {r.rule_type:10} {r.value}{' @' + r.chain if r.chain else ''}  ({conf}, {r.source})")
        if p.testing_restrictions:
            click.echo("  restrictions:")
            for t in p.testing_restrictions:
                click.echo(f"    - {t}")


@scope.command("import")
@click.argument("program")
@click.argument("path", type=click.File())
def scope_import(program, path):
    """Confirm scope from a YAML file the program gave you in writing."""
    with session_scope() as s:
        p = _program(s, program)
        manager.confirm_scope_manually(s, p, yaml.safe_load(path) or {})
        click.echo(f"{p.name}: scope {p.scope_status}, state {p.authorization_status}")


@scope.command("check")
@click.argument("program")
@click.argument("asset")
@click.option("--chain")
def scope_check(program, asset, chain):
    """Check one asset against confirmed scope."""
    with session_scope() as s:
        p = _program(s, program)
        d = scope_engine.evaluate(p.scope_rules, asset, chain=chain, require_confirmed=get_settings().require_explicit_scope)
        click.echo(f"{asset}: {d.status} ({d.detail})")


# ------------------------------------------------------------------- assets
@main.command()
@click.argument("program")
@click.option("--passive", is_flag=True, help="Also run passive discovery (authorized programs only).")
def assets(program, passive):
    """Build and show the asset inventory for a program."""
    with session_scope() as s:
        p = _program(s, program)
        if passive:
            try:
                intelligence.discover_passive(s, p)
            except intelligence.NotAuthorizedForIntel as exc:
                raise click.ClickException(str(exc))
        else:
            intelligence.sync_from_scope(s, p)
        for a in sorted(p.assets, key=lambda a: (a.scope_status, a.asset_type, a.identifier)):
            click.echo(f"  {a.scope_status:13} {a.asset_type:10} {a.identifier}{' @' + a.chain if a.chain else ''}  [{a.source}]")


@main.command("research-ready")
@click.option("--json", "as_json", is_flag=True)
def research_ready(as_json):
    """Programs whose authorization gates are all satisfied."""
    with session_scope() as s:
        ready = [p for p in s.scalars(select(Program).where(Program.authorization_status == AuthState.READY_FOR_RESEARCH))
                 if not manager.gates_satisfied(p, get_settings())]
        _emit(ready, as_json, label="READY")
        if not get_settings().research_mode:
            click.echo("RESEARCH_MODE=false: research actions stay blocked until you enable it in the environment.")


@main.command()
@click.option("--limit", default=50, show_default=True)
def blocked(limit):
    """Recent research actions the gate blocked."""
    with session_scope() as s:
        rows = s.scalars(select(AuditEvent).where(AuditEvent.event_type == AuditEventType.RESEARCH_BLOCKED)
                         .order_by(AuditEvent.id.desc()).limit(limit))
        for e in rows:
            click.echo(json.dumps({k: e.payload.get(k) for k in ("asset", "reason", "timestamp", "action")}))


@main.command()
@click.option("--format", "fmt", type=click.Choice(["md", "json"]), default="md")
@click.option("--output", type=click.Path(path_type=Path))
def report(fmt, output):
    """Summary report of programs, authorization and the audit chain."""
    with session_scope() as s:
        text = reporting.render(s, fmt)
    if output:
        output.write_text(text)
        click.echo(f"wrote {output}")
    else:
        click.echo(text)


@main.command("audit")
@click.option("--limit", default=50, show_default=True)
@click.option("--verify-chain", is_flag=True)
def audit_cmd(limit, verify_chain):
    """Show the append-only audit log."""
    with session_scope() as s:
        if verify_chain:
            ok, bad = audit.verify_chain(s)
            click.echo("audit chain intact" if ok else f"audit chain broken at event #{bad}")
            sys.exit(0 if ok else 1)
        for e in s.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)):
            click.echo(f"#{e.id} {e.created_at:%Y-%m-%d %H:%M:%S} {e.event_type:32} program={e.program_id} {json.dumps(e.payload, default=str)[:200]}")


# ----------------------------------------------------------------- research
@main.group()
def research():
    """Gated research module. Every command passes the authorization gate."""


@research.command("check")
@click.argument("asset")
@click.option("--method", type=click.Choice([m.value for m in ResearchMethod]), default=ResearchMethod.STATIC_ANALYSIS.value)
@click.option("--program", "program_ref")
@click.option("--chain")
def research_check(asset, method, program_ref, chain):
    """Ask the gate whether an action would be allowed (blocked checks are logged)."""
    with session_scope() as s:
        pid = _program(s, program_ref).id if program_ref else None
        d = check_authorization(s, asset, method, program_id=pid, chain=chain)
        click.echo(json.dumps(d.as_event(), indent=2))
    # Exit only after the session committed, so the blocked event is kept.
    if not d.allowed:
        sys.exit(2)


@research.command("static")
@click.argument("address")
@click.option("--chain", required=True)
@click.option("--program", "program_ref", required=True)
def research_static(address, chain, program_ref):
    """Run Slither on a verified, in-scope contract (needs every gate)."""
    try:
        with session_scope() as s:
            rs = runner.run_static_analysis(s, address.lower(), chain, _program(s, program_ref).id)
            click.echo(f"session #{rs.id}: {rs.status}")
    except AuthorizationBlocked as exc:
        raise click.ClickException(str(exc))


@main.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8000)
def serve(host, port):
    """Run the API server (dashboard backend)."""
    import uvicorn

    uvicorn.run("crawler.api.app:app", host=host, port=port)


if __name__ == "__main__":
    main()
