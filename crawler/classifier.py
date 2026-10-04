"""Program classification: how private is this program?

The classification only ever affects priority. It never grants
authorization: an unlisted or hidden program is a reason to ask, not a
reason to test.
"""

from __future__ import annotations

import re

from .enums import Classification, ProgramType
from .normalizer import NormalizedProgram

PRIVATE_HINTS = [
    (r"\binvite[- ]only\b|\bby invitation\b|\binvitation[- ]only\b", "invite-only wording"),
    (r"\bprivate (bug bounty|program|bounty)\b", "private program wording"),
    (r"\bapply (to|for) (join|access|the program)\b|\bapplication[- ]based\b|\bapply to participate\b", "application-based wording"),
    (r"\bresearcher[- ]specific\b|\bselected researchers\b|\bvetted researchers\b", "researcher-specific wording"),
    (r"\bcontact (our|the) security team\b.*\b(access|scope|program)\b|\bemail (us|security@)[^.]*\b(access|participate)\b", "access through the security team"),
]
VDP_HINTS = [
    r"\bvulnerability disclosure (program|policy)\b",
    r"\bno (monetary )?(rewards?|bount(y|ies))\b",
    r"\bnot offer (a )?(monetary )?(rewards?|bount(y|ies))\b",
    r"\bhall of fame\b",
]
BOUNTY_HINTS = [r"\bbug bounty\b", r"\brewards? (of )?up to\b", r"\$\s?\d"]


def classify(program: NormalizedProgram) -> tuple[Classification, list[str]]:
    text = " ".join(
        str(x or "")
        for x in (program.notes, program.disclosure_policy, program.payment_info, program.raw.get("description"))
    ).lower()
    reasons: list[str] = []

    if program.private_acknowledged and program.program_type in (
        ProgramType.PRIVATE,
        ProgramType.INVITE_ONLY,
    ):
        reasons.append("source officially acknowledges a private/invite-only program")
        return Classification.PRIVATE_CONFIRMED, reasons

    private_signals = []
    if program.program_type in (ProgramType.PRIVATE, ProgramType.INVITE_ONLY):
        private_signals.append(f"source lists program type as {program.program_type.value}")
    if program.invite_required:
        private_signals.append("program requires an invitation")
    if program.application_required:
        private_signals.append("program requires an application")
    for pattern, label in PRIVATE_HINTS:
        if re.search(pattern, text):
            private_signals.append(label)
    if program.platform == "direct" and program.security_email and not program.max_bounty:
        private_signals.append("only reachable through direct security-team contact")

    has_bounty = bool(program.max_bounty) or any(re.search(p, text) for p in BOUNTY_HINTS)
    vdp = program.program_type == ProgramType.VDP or any(re.search(p, text) for p in VDP_HINTS)

    if private_signals:
        reasons.extend(private_signals)
        reasons.append("not treated as authorization; confirmation from the project is required")
        return Classification.PRIVATE_POSSIBLE, reasons
    if vdp and not program.max_bounty:
        reasons.append("disclosure program without monetary rewards")
        return Classification.VDP_ONLY, reasons
    if program.program_type == ProgramType.PUBLIC or has_bounty:
        reasons.append("publicly listed program")
        return Classification.PUBLIC, reasons
    reasons.append("not enough information to classify")
    return Classification.UNKNOWN, reasons


PRIORITY = {
    Classification.PRIVATE_CONFIRMED: 0,
    Classification.PRIVATE_POSSIBLE: 1,
    Classification.UNKNOWN: 2,
    Classification.PUBLIC: 3,
    Classification.VDP_ONLY: 4,
}
