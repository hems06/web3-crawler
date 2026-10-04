"""Classify replies to authorization requests and extract scope details.

The parser is conservative on purpose:
  * friendly but vague replies ("feel free to look around", "we appreciate
    security researchers") are NOT authorization;
  * authorization needs an explicit grant sentence without negation;
  * scope is only confirmed when the reply names concrete assets.
Its output is a suggestion. A person reviews it before it is applied.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from ..enums import ResponseClass as R
from ..normalizer import EMAIL_RE, parse_money
from ..scope.engine import KNOWN_CHAINS, normalize_domain, normalize_repo

EXPLICIT_GRANT = [
    r"\byou are (hereby )?(authori[sz]ed|permitted|allowed|cleared|approved) to (test|perform|conduct|research|assess)",
    r"\bwe (hereby )?(authori[sz]e|permit|allow|approve) you to (test|perform|conduct|research|assess)",
    r"\b(written )?authori[sz]ation (is|has been) (hereby )?granted\b",
    r"\byou have (our )?(explicit |written )?(permission|authori[sz]ation) to (test|perform|conduct|research|assess)",
    r"\b(security )?testing is (explicitly )?(permitted|authori[sz]ed|allowed|approved)\b",
    r"\byou (may|can) (begin|start) testing\b",
    r"\bapproved to (test|conduct|perform)\b",
    r"\bpermission (is )?granted\b",
]
# Phrases that sound welcoming but grant nothing.
VAGUE_PHRASES = [
    r"feel free to (look around|poke around|have a look|explore)",
    r"we appreciate (security )?researchers",
    r"thanks? for (your|reaching)",
    r"happy to hear from (you|researchers)",
]
NEGATION = re.compile(r"\b(not|no|never|cannot|can't|won't|don't|do not|isn't|aren't|unable|without)\b", re.I)
DENIAL = [
    r"\bnot (authori[sz]ed|permitted|allowed) to (test|perform|conduct)",
    r"\bdo not (test|perform any testing|conduct)",
    r"\bplease (do not|don't|refrain from) (test|perform|conduct|scan)",
    r"\bwe (do not|don't) (permit|allow|authori[sz]e)",
    r"\btesting is (not|strictly) (permitted|allowed|prohibited)",
    r"\bnot accepting (external )?(security )?(reports|research)",
]
GLOBAL_DENIAL = re.compile(
    r"\b(any|anything|at all|at this time|for now|our (systems|infrastructure|services|protocol|platform|production)|you are not (authori[sz]ed|permitted|allowed))\b",
    re.I,
)
DECLINE = [r"\b(we|i) (must|have to|will) decline\b", r"\bdeclin(e|ing) (your|this) request\b"]
CONDITIONAL = [
    r"\bonce you (sign|agree|complete|accept)",
    r"\bafter (you )?(sign|signing|completing|kyc|agreeing)",
    r"\b(nda|kyc)\b.*\b(required|first|before)\b",
    r"\bpending (approval|review|legal)\b",
    r"\bpartial(ly)? (authori[sz]|approv)",
    r"\blimited authori[sz]ation\b",
    r"\bwe will (confirm|get back|follow up) (the )?scope\b",
]
SCOPE_UNCLEAR = [
    r"\bscope (is |will be )?(tbd|to be determined|not (yet )?(defined|finali[sz]ed|decided))\b",
    r"\bwe will (share|send|confirm) (the )?scope\b",
    r"\bscope (is )?(still )?(under review|being finali[sz]ed)\b",
]
BOUNTY_NO = [
    r"\bno (monetary |cash |financial )?(bount(y|ies)|rewards?|payouts?)\b",
    r"\b(do not|don't|cannot|can't|unable to) (offer|pay|provide) (a |any )?(monetary |cash )?(bount(y|ies)|rewards?)",
    r"\bnot eligible for (a |any )?(monetary )?(bount(y|ies)|rewards?)",
    r"\b(vdp|vulnerability disclosure program) only\b",
    r"\bunpaid\b",
]
BOUNTY_YES = [
    r"\beligible for (a |the )?(monetary |cash )?(bount(y|ies)|rewards?|payouts?)",
    r"\bbount(y|ies) (of )?up to\b",
    r"\brewards? (of )?up to\b",
    r"\bwe (will |do )?(offer|pay) (a )?(bount(y|ies)|rewards?)",
    r"\bbounty (program )?is (active|available)\b",
]
SCOPE_STATEMENT = re.compile(r"\bin[- ]scope\b|\bscope (is|includes|covers|consists)\b|\bauthori[sz]ed (assets|scope|targets)\b", re.I)
_HEADER = r"^\s*(?:#+\s*|\*\*)?(?:{})\b[^.:;,]{{0,30}}:?\**\s*$"
SCOPE_HEADER = re.compile(_HEADER.format(r"in[- ]scope|scope|authori[sz]ed (?:assets|scope|targets)"), re.I)
OUT_HEADER = re.compile(_HEADER.format(r"out[- ]of[- ]scope|excluded|exclusions"), re.I)
RESTRICT_HEADER = re.compile(_HEADER.format(r"restrictions|rules|prohibited|testing (?:rules|restrictions)"), re.I)

ADDRESS_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
REPO_RE = re.compile(r"(?:https?://)?(?:www\.)?github\.com/[\w.-]+/[\w.-]+", re.I)
URL_RE = re.compile(r"https?://[^\s<>()\"']+", re.I)
DOMAIN_RE = re.compile(r"(?<![@\w.-])(\*\.)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|io|xyz|org|net|finance|fi|app|dev|exchange|network|money|co|gg|ai|so|tech|link|dao|protocol|eth|trade|markets|capital|sh|me|info|us|uk|de|ch))\b", re.I)
AMOUNT_RE = re.compile(r"(?:\$\s?\d[\d,]*(?:\.\d+)?\s?[kKmM]?\b|\b\d[\d,]*(?:\.\d+)?\s?[kKmM]?\s?(?:USDC|USDT|DAI|USD|ETH)\b)")
SEVERITY_LINE = re.compile(r"\b(critical|high|medium|low)\b[^.\n]{0,120}", re.I)
DATE_PATTERNS = [
    r"\d{4}-\d{2}-\d{2}",
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\.? \d{1,2},? \d{4}",
    r"\d{1,2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]* \d{4}",
]
EXPIRY_RE = re.compile(
    r"\b(?:valid (?:until|through|till)|expires?(?: on)?|until|through|ends? on)\s*:?\s*(" + "|".join(DATE_PATTERNS) + ")",
    re.I,
)
API_HINT = re.compile(r"(^|[./])(api|rpc|graphql|gateway)([./-]|$)", re.I)
AMBIGUOUS_CHAIN_WORDS = {"base", "near", "sonic", "scroll", "blast", "mantle", "eth", "mainnet", "matic", "avax", "op mainnet"}
METHOD_KEYWORDS = {
    "denial_of_service": r"\b(dos|ddos|denial[- ]of[- ]service|load test|stress test)",
    "social_engineering": r"\bsocial engineering\b",
    "phishing": r"\bphishing\b",
    "brute_force": r"\bbrute[- ]?forc",
    "active_scan": r"\b(automated scan|vulnerability scanner|scanners?|automated tools?)\b",
    "exploit_live": r"\b(mainnet|production|live (network|contracts|systems))\b",
}


@dataclass
class ParsedResponse:
    classifications: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    contracts: list[str] = field(default_factory=list)
    repositories: list[str] = field(default_factory=list)
    apis: list[str] = field(default_factory=list)
    chains: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    restrictions: list[str] = field(default_factory=list)
    prohibited_methods: list[str] = field(default_factory=list)
    bounty_amounts: list[str] = field(default_factory=list)
    max_bounty: float | None = None
    bounty_currency: str | None = None
    severity_definitions: list[str] = field(default_factory=list)
    expiration: str | None = None
    security_contacts: list[str] = field(default_factory=list)
    submission_method: str | None = None
    evidence: list[str] = field(default_factory=list)
    declined: bool = False

    def has(self, cls: R) -> bool:
        return cls.value in self.classifications

    @property
    def scope_assets(self) -> int:
        return len(self.domains) + len(self.contracts) + len(self.repositories) + len(self.apis)

    def to_dict(self) -> dict:
        return asdict(self)


def _sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    return [p.strip() for p in parts if p.strip()]


def _any(patterns, text) -> re.Match | None:
    for p in patterns:
        m = re.search(p, text, re.I)
        if m:
            return m
    return None


def _strip_quoted(body: str) -> str:
    """Drop quoted history (lines starting with '>' and 'On ... wrote:' tails)
    so our own request text is never read back as the program's answer."""
    lines = []
    for line in body.splitlines():
        if re.match(r"^\s*On .+wrote:\s*$", line):
            break
        if line.lstrip().startswith(">"):
            continue
        lines.append(line)
    return "\n".join(lines)


def _parse_date(text: str) -> str | None:
    for fmt in ("%Y-%m-%d", "%B %d, %Y", "%B %d %Y", "%b %d, %Y", "%b %d %Y", "%d %B %Y", "%d %b %Y"):
        try:
            return datetime.strptime(text.replace("Sept", "Sep").replace(".", ""), fmt).replace(tzinfo=timezone.utc).date().isoformat()
        except ValueError:
            continue
    return None


def parse_response(body: str, subject: str | None = None) -> ParsedResponse:
    text = _strip_quoted(body or "")
    out = ParsedResponse()
    sentences = _sentences(text)

    granted = denied = declined = conditional = False
    scoped_denials: list[str] = []
    for s in sentences:
        if _any(DENIAL, s):
            # "Do not test on mainnet" next to a grant is a restriction;
            # "do not test any of our systems" is a refusal.
            if GLOBAL_DENIAL.search(s):
                denied = True
            else:
                scoped_denials.append(s)
            out.evidence.append(s)
            continue
        if _any(DECLINE, s):
            declined = True
            out.evidence.append(s)
            continue
        m = _any(EXPLICIT_GRANT, s)
        if m:
            before = s[: m.start()]
            if NEGATION.search(before) or NEGATION.search(m.group(0)):
                denied = True
            else:
                granted = True
            out.evidence.append(s)
        if _any(CONDITIONAL, s):
            conditional = True
            out.evidence.append(s)

    if scoped_denials and not granted:
        denied = True

    # --- section-aware asset extraction --------------------------------
    section, section_lines = "body", 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            if section_lines:  # a blank line after a list ends that section
                section, section_lines = "body", 0
            continue
        if section != "body":
            section_lines += 1
        if OUT_HEADER.match(line):
            section, section_lines = "out", 0
            continue
        if SCOPE_HEADER.match(line):
            section, section_lines = "in", 0
            continue
        if RESTRICT_HEADER.match(line):
            section, section_lines = "restrict", 0
            continue
        lower = line.lower()
        line_out = section == "out" or "out of scope" in lower or "out-of-scope" in lower or "excluded" in lower
        if section == "restrict" or re.search(r"\b(do not|don't|must not|prohibited|not allowed|not permitted|forbidden|refrain)\b", lower):
            out.restrictions.append(line.lstrip("-*• ").strip())

        found: list[str] = []
        for addr in ADDRESS_RE.findall(line):
            found.append(addr.lower())
            if not line_out:
                out.contracts.append(addr.lower())
        line_wo_addr = ADDRESS_RE.sub(" ", line)
        for repo in REPO_RE.findall(line_wo_addr):
            norm = normalize_repo(repo)
            if norm:
                found.append(norm)
                if not line_out:
                    out.repositories.append(norm)
        line_wo_repo = REPO_RE.sub(" ", line_wo_addr)
        for url in URL_RE.findall(line_wo_repo):
            url = url.rstrip(".,;:)")
            host = normalize_domain(url)
            if API_HINT.search(host) or API_HINT.search(url.split(host, 1)[-1]):
                found.append(url)
                if not line_out:
                    out.apis.append(url)
        line_wo_url = URL_RE.sub(lambda m: " " + normalize_domain(m.group(0)) + " ", line_wo_repo)
        line_wo_email = EMAIL_RE.sub(" ", line_wo_url)
        for m in DOMAIN_RE.finditer(line_wo_email):
            dom = (m.group(1) or "") + m.group(2).lower()
            if dom in ("github.com", "etherscan.io") or dom in found:
                continue
            found.append(dom)
            if not line_out:
                out.domains.append(dom)
        if line_out:
            if found:
                out.out_of_scope.extend(found)
            elif section == "out":
                out.out_of_scope.append(line.lstrip("-*• ").strip())

    for key, name in KNOWN_CHAINS.items():
        if key in AMBIGUOUS_CHAIN_WORDS:
            # Ordinary English words only count when written as a proper name.
            hit = re.search(r"\b" + re.escape(key.title()) + r"\b", text)
        else:
            hit = re.search(r"\b" + re.escape(key) + r"\b", text, re.I)
        if hit and name not in out.chains:
            out.chains.append(name)
    out.chains.sort()

    for method, pattern in METHOD_KEYWORDS.items():
        if any(re.search(pattern, r, re.I) for r in out.restrictions):
            out.prohibited_methods.append(method)

    out.bounty_amounts = [a.strip() for a in AMOUNT_RE.findall(text)]
    if out.bounty_amounts:
        out.max_bounty, out.bounty_currency = parse_money(" ".join(out.bounty_amounts))
    out.severity_definitions = [m.group(0).strip() for m in SEVERITY_LINE.finditer(text) if re.search(r"\$|\d|usd|reward|bounty", m.group(0), re.I)]
    m = EXPIRY_RE.search(text)
    if m:
        out.expiration = _parse_date(m.group(1))
    out.security_contacts = sorted({e.lower() for e in EMAIL_RE.findall(text)})
    sub = re.search(
        r"\b(submit|send|report)\w*\b[^.\n]{0,40}?\b(via|through|using|at|to)\s+"
        r"(?:[\w.+-]+@[\w.-]+\w|https?://\S+|(?:our|the) [^.\n]{0,60}?(?:portal|form|platform|email|inbox|page))",
        text,
        re.I,
    )
    out.submission_method = sub.group(0).strip().rstrip(".") if sub else None

    for field_name in ("domains", "contracts", "repositories", "apis", "out_of_scope", "restrictions"):
        seen, uniq = set(), []
        for v in getattr(out, field_name):
            if v not in seen:
                seen.add(v)
                uniq.append(v)
        setattr(out, field_name, uniq)
    out.domains = [d for d in out.domains if d not in out.out_of_scope]

    # --- classification -----------------------------------------------------
    cls: list[R] = []
    if denied or declined:
        cls.append(R.NOT_AUTHORIZED)
    elif granted and conditional:
        cls.append(R.PARTIALLY_AUTHORIZED)
    elif granted:
        cls.append(R.AUTHORIZED)

    if R.AUTHORIZED in cls or R.PARTIALLY_AUTHORIZED in cls:
        if _any(SCOPE_UNCLEAR, text) or out.scope_assets == 0:
            cls.append(R.SCOPE_REQUIRES_CLARIFICATION)
        else:
            cls.append(R.SCOPE_CONFIRMED)
    elif R.NOT_AUTHORIZED not in cls and out.scope_assets and SCOPE_STATEMENT.search(text):
        # A follow-up that only states scope. It is applied only to a program
        # that already holds an explicit authorization.
        cls.append(R.SCOPE_CONFIRMED)

    no_bounty = any(_any(BOUNTY_NO, s) for s in sentences)
    yes_bounty = any(_any(BOUNTY_YES, s) and not _any(BOUNTY_NO, s) for s in sentences)
    if no_bounty:
        cls.append(R.BOUNTY_NOT_AVAILABLE)
        out.evidence.extend(s for s in sentences if _any(BOUNTY_NO, s))
    elif yes_bounty:
        cls.append(R.BOUNTY_CONFIRMED)
        out.evidence.extend(s for s in sentences if _any(BOUNTY_YES, s))

    if not cls:
        cls.append(R.UNKNOWN)
        vague = [s for s in sentences if _any(VAGUE_PHRASES, s)]
        if vague:
            out.evidence.extend(vague)
    out.classifications = [c.value for c in cls]
    out.declined = declined
    out.evidence = list(dict.fromkeys(out.evidence))
    return out
