"""Authorization request email. Generated only; sending is a separate,
user-approved step (see manager.send_request)."""

from __future__ import annotations

SUBJECT = "Security Research / Bug Bounty Authorization Request — {project}"

BODY = """Hello {team},

I am an independent security researcher interested in conducting responsible security research against {project}.

Before performing any testing, I would like to confirm:

1. Whether your organization currently accepts external security reports.
2. Whether security testing is permitted against your Web3 infrastructure/protocol.
3. Whether there is an active bug bounty or vulnerability disclosure program.
4. Whether researchers are eligible for monetary rewards.
5. Which assets/contracts/domains are explicitly in scope.
6. Which testing techniques are prohibited.
7. Whether prior written authorization is required.
8. Whether there is a preferred security contact or submission portal.

I will not perform testing against systems outside the explicitly authorized scope.
{listed_note}
Please confirm the applicable scope and bounty terms before I begin any testing.

Regards,
{researcher_name}
{researcher_contact}
"""


def generate(program, researcher_name: str, researcher_contact: str, team: str | None = None) -> tuple[str, str]:
    project = program.protocol_name or program.project_name or program.name
    listed = [s.get("value") for s in (program.listed_scope or []) if s.get("value")]
    listed_note = ""
    if listed:
        shown = ", ".join(listed[:10]) + (" and others" if len(listed) > 10 else "")
        listed_note = (
            f"\nI found these assets listed publicly ({shown}). I have not tested any of them "
            "and would like you to confirm whether they are in scope.\n"
        )
    subject = SUBJECT.format(project=project)
    body = BODY.format(
        team=team or f"{project} Security Team",
        project=project,
        listed_note=listed_note,
        researcher_name=researcher_name,
        researcher_contact=researcher_contact,
    )
    return subject, body
