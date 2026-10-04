"""Shared enumerations. Stored as plain strings so SQLite and Postgres agree."""

from enum import StrEnum


class ProgramType(StrEnum):
    """What the source says the program is."""

    PUBLIC = "public"
    PRIVATE = "private"
    INVITE_ONLY = "invite_only"
    VDP = "vdp"
    UNKNOWN = "unknown"


class Classification(StrEnum):
    """What the classifier concludes about how private the program is."""

    PRIVATE_CONFIRMED = "PRIVATE_CONFIRMED"
    PRIVATE_POSSIBLE = "PRIVATE_POSSIBLE"
    PUBLIC = "PUBLIC"
    VDP_ONLY = "VDP_ONLY"
    UNKNOWN = "UNKNOWN"


class AuthState(StrEnum):
    DISCOVERED = "DISCOVERED"
    PRIVATE_CANDIDATE = "PRIVATE_CANDIDATE"
    AUTHORIZATION_REQUESTED = "AUTHORIZATION_REQUESTED"
    AWAITING_RESPONSE = "AWAITING_RESPONSE"
    AUTHORIZED = "AUTHORIZED"
    SCOPE_CONFIRMED = "SCOPE_CONFIRMED"
    BOUNTY_CONFIRMED = "BOUNTY_CONFIRMED"
    READY_FOR_RESEARCH = "READY_FOR_RESEARCH"
    # negative states
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    DECLINED = "DECLINED"
    NO_RESPONSE = "NO_RESPONSE"
    VDP_ONLY = "VDP_ONLY"
    BOUNTY_NOT_AVAILABLE = "BOUNTY_NOT_AVAILABLE"
    SCOPE_UNCLEAR = "SCOPE_UNCLEAR"
    EXPIRED_AUTHORIZATION = "EXPIRED_AUTHORIZATION"


class ScopeStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    LISTED = "LISTED"  # published by the platform/program, not confirmed to us
    CONFIRMED = "CONFIRMED"
    UNCLEAR = "UNCLEAR"


class BountyStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    LISTED = "LISTED"
    CONFIRMED = "CONFIRMED"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class AssetScope(StrEnum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    SCOPE_UNKNOWN = "SCOPE_UNKNOWN"


class AssetType(StrEnum):
    DOMAIN = "domain"
    CONTRACT = "contract"
    REPOSITORY = "repository"
    CHAIN = "chain"
    API = "api"
    RPC = "rpc"
    PACKAGE = "package"
    DOCKER_IMAGE = "docker_image"
    DOCUMENTATION = "documentation"
    OTHER = "other"


class RequestStatus(StrEnum):
    DRAFT = "DRAFT"
    APPROVED = "APPROVED"
    SENT = "SENT"
    CANCELLED = "CANCELLED"


class ResponseClass(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    PARTIALLY_AUTHORIZED = "PARTIALLY_AUTHORIZED"
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    BOUNTY_CONFIRMED = "BOUNTY_CONFIRMED"
    BOUNTY_NOT_AVAILABLE = "BOUNTY_NOT_AVAILABLE"
    SCOPE_CONFIRMED = "SCOPE_CONFIRMED"
    SCOPE_REQUIRES_CLARIFICATION = "SCOPE_REQUIRES_CLARIFICATION"
    UNKNOWN = "UNKNOWN"


class ResearchMethod(StrEnum):
    """Research techniques the gate knows about.

    Nothing in v1 performs active testing; these names exist so the gate can
    reason about what an action would be.
    """

    PASSIVE_RECON = "passive_recon"
    STATIC_ANALYSIS = "static_analysis"
    LOCAL_FORK_TESTING = "local_fork_testing"
    LOCAL_FUZZING = "local_fuzzing"
    ACTIVE_SCAN = "active_scan"
    # Never permitted, whatever a program says.
    EXPLOIT_LIVE = "exploit_live"
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_ATTACK = "credential_attack"
    DENIAL_OF_SERVICE = "denial_of_service"
    PHISHING = "phishing"
    SOCIAL_ENGINEERING = "social_engineering"
    AUTH_BYPASS = "auth_bypass"


FORBIDDEN_METHODS = frozenset(
    {
        ResearchMethod.EXPLOIT_LIVE,
        ResearchMethod.BRUTE_FORCE,
        ResearchMethod.CREDENTIAL_ATTACK,
        ResearchMethod.DENIAL_OF_SERVICE,
        ResearchMethod.PHISHING,
        ResearchMethod.SOCIAL_ENGINEERING,
        ResearchMethod.AUTH_BYPASS,
    }
)

# Methods that never touch live infrastructure. These are permitted by default
# once a program is authorized; anything else must be explicitly permitted by
# the program.
DEFAULT_PERMITTED_METHODS = frozenset(
    {
        ResearchMethod.PASSIVE_RECON,
        ResearchMethod.STATIC_ANALYSIS,
        ResearchMethod.LOCAL_FORK_TESTING,
        ResearchMethod.LOCAL_FUZZING,
    }
)


class AuditEventType(StrEnum):
    PROGRAM_DISCOVERED = "program_discovered"
    PROGRAM_CLASSIFIED = "program_classified"
    AUTHORIZATION_STATE_CHANGED = "authorization_state_changed"
    AUTHORIZATION_EMAIL_GENERATED = "authorization_email_generated"
    AUTHORIZATION_EMAIL_APPROVED = "authorization_email_approved"
    AUTHORIZATION_EMAIL_SENT = "authorization_email_sent"
    AUTHORIZATION_RESPONSE_RECEIVED = "authorization_response_received"
    AUTHORIZATION_RESPONSE_APPLIED = "authorization_response_applied"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    SCOPE_UPDATED = "scope_updated"
    BOUNTY_CONFIRMED = "bounty_confirmed"
    ASSET_DISCOVERED = "asset_discovered"
    RESEARCH_STARTED = "research_started"
    RESEARCH_BLOCKED = "research_blocked"
    FINDING_CREATED = "finding_created"
