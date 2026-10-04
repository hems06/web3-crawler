"""SQLAlchemy models. Column types are portable between SQLite and Postgres."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .enums import (
    AssetScope,
    AuthState,
    BountyStatus,
    Classification,
    ProgramType,
    RequestStatus,
    ScopeStatus,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    type_annotation_map = {datetime: DateTime(timezone=True)}


class Platform(Base):
    __tablename__ = "platforms"

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(128))
    url: Mapped[str | None] = mapped_column(String(512))
    has_reputation_system: Mapped[bool] = mapped_column(Boolean, default=False)
    platform_reputation_required: Mapped[bool] = mapped_column(Boolean, default=False)
    invite_required: Mapped[bool] = mapped_column(Boolean, default=False)
    application_required: Mapped[bool] = mapped_column(Boolean, default=False)
    private_program_supported: Mapped[bool] = mapped_column(Boolean, default=False)

    programs: Mapped[list["Program"]] = relationship(back_populates="platform")


class Program(Base):
    __tablename__ = "programs"
    __table_args__ = (UniqueConstraint("dedupe_key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    dedupe_key: Mapped[str] = mapped_column(String(512))
    name: Mapped[str] = mapped_column(String(256))
    project_name: Mapped[str | None] = mapped_column(String(256))
    protocol_name: Mapped[str | None] = mapped_column(String(256))
    platform_id: Mapped[int] = mapped_column(ForeignKey("platforms.id"))
    program_url: Mapped[str | None] = mapped_column(String(1024))
    source_url: Mapped[str | None] = mapped_column(String(1024))
    collector: Mapped[str | None] = mapped_column(String(64))

    program_type: Mapped[str] = mapped_column(String(32), default=ProgramType.UNKNOWN)
    classification: Mapped[str] = mapped_column(String(32), default=Classification.UNKNOWN)
    classification_reasons: Mapped[list] = mapped_column(JSON, default=list)

    # Access properties (platform defaults, overridden by program evidence).
    platform_reputation_required: Mapped[bool] = mapped_column(Boolean, default=False)
    invite_required: Mapped[bool] = mapped_column(Boolean, default=False)
    application_required: Mapped[bool] = mapped_column(Boolean, default=False)
    private_program_supported: Mapped[bool] = mapped_column(Boolean, default=False)

    # What the source published. Listed scope is NOT confirmed scope.
    listed_scope: Mapped[list] = mapped_column(JSON, default=list)
    listed_out_of_scope: Mapped[list] = mapped_column(JSON, default=list)
    max_severity: Mapped[str | None] = mapped_column(String(32))
    max_bounty: Mapped[float | None] = mapped_column(Float)
    bounty_currency: Mapped[str | None] = mapped_column(String(32))
    payment_info: Mapped[str | None] = mapped_column(Text)
    safe_harbor: Mapped[str | None] = mapped_column(Text)
    disclosure_policy: Mapped[str | None] = mapped_column(Text)
    program_status: Mapped[str | None] = mapped_column(String(32))
    source_last_updated: Mapped[datetime | None] = mapped_column()
    security_email: Mapped[str | None] = mapped_column(String(256))
    notes: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)

    authorization_status: Mapped[str] = mapped_column(String(32), default=AuthState.DISCOVERED)
    scope_status: Mapped[str] = mapped_column(String(32), default=ScopeStatus.UNKNOWN)
    bounty_status: Mapped[str] = mapped_column(String(32), default=BountyStatus.UNKNOWN)
    authorized_at: Mapped[datetime | None] = mapped_column()
    authorization_expires_at: Mapped[datetime | None] = mapped_column()
    authorization_evidence: Mapped[str | None] = mapped_column(Text)
    permitted_methods: Mapped[list] = mapped_column(JSON, default=list)
    prohibited_methods: Mapped[list] = mapped_column(JSON, default=list)
    testing_restrictions: Mapped[list] = mapped_column(JSON, default=list)

    opportunity_score: Mapped[float] = mapped_column(Float, default=0.0)
    discovered_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_verified: Mapped[datetime | None] = mapped_column()

    platform: Mapped[Platform] = relationship(back_populates="programs")
    assets: Mapped[list["Asset"]] = relationship(back_populates="program")
    scope_rules: Mapped[list["ScopeRule"]] = relationship(back_populates="program")
    authorization_requests: Mapped[list["AuthorizationRequest"]] = relationship(
        back_populates="program"
    )
    bounty_terms: Mapped[list["BountyTerms"]] = relationship(back_populates="program")


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("program_id", "asset_type", "identifier", "chain"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    asset_type: Mapped[str] = mapped_column(String(32))
    identifier: Mapped[str] = mapped_column(String(512))
    chain: Mapped[str | None] = mapped_column(String(64))
    source: Mapped[str | None] = mapped_column(String(128))
    scope_status: Mapped[str] = mapped_column(String(32), default=AssetScope.SCOPE_UNKNOWN)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    discovered_at: Mapped[datetime] = mapped_column(default=utcnow)

    program: Mapped[Program] = relationship(back_populates="assets")


class Contract(Base):
    __tablename__ = "contracts"
    __table_args__ = (UniqueConstraint("program_id", "address", "chain"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"))
    address: Mapped[str] = mapped_column(String(64))
    chain: Mapped[str | None] = mapped_column(String(64))
    compiler_version: Mapped[str | None] = mapped_column(String(64))
    is_proxy: Mapped[bool | None] = mapped_column(Boolean)
    implementation_address: Mapped[str | None] = mapped_column(String(64))
    verified_source: Mapped[bool | None] = mapped_column(Boolean)
    verification_source: Mapped[str | None] = mapped_column(String(64))
    abi_available: Mapped[bool | None] = mapped_column(Boolean)
    upgradeable: Mapped[bool | None] = mapped_column(Boolean)
    owner: Mapped[str | None] = mapped_column(String(64))
    admin_roles: Mapped[list] = mapped_column(JSON, default=list)
    external_dependencies: Mapped[list] = mapped_column(JSON, default=list)
    fetched_at: Mapped[datetime | None] = mapped_column()


class AuthorizationRequest(Base):
    __tablename__ = "authorization_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    recipient: Mapped[str | None] = mapped_column(String(256))
    subject: Mapped[str] = mapped_column(String(512))
    body: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default=RequestStatus.DRAFT)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    approved_at: Mapped[datetime | None] = mapped_column()
    sent_at: Mapped[datetime | None] = mapped_column()
    sent_via: Mapped[str | None] = mapped_column(String(32))

    program: Mapped[Program] = relationship(back_populates="authorization_requests")
    responses: Mapped[list["AuthorizationResponse"]] = relationship(back_populates="request")


class AuthorizationResponse(Base):
    __tablename__ = "authorization_responses"

    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    request_id: Mapped[int | None] = mapped_column(ForeignKey("authorization_requests.id"))
    received_at: Mapped[datetime] = mapped_column(default=utcnow)
    sender: Mapped[str | None] = mapped_column(String(256))
    subject: Mapped[str | None] = mapped_column(String(512))
    body: Mapped[str] = mapped_column(Text)
    classifications: Mapped[list] = mapped_column(JSON, default=list)
    extracted: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    applied_at: Mapped[datetime | None] = mapped_column()

    request: Mapped[AuthorizationRequest | None] = relationship(back_populates="responses")


class ScopeRule(Base):
    __tablename__ = "scope_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    rule_type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(512))
    chain: Mapped[str | None] = mapped_column(String(64))
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(64))
    evidence_response_id: Mapped[int | None] = mapped_column(
        ForeignKey("authorization_responses.id")
    )
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    program: Mapped[Program] = relationship(back_populates="scope_rules")


class BountyTerms(Base):
    __tablename__ = "bounty_terms"

    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    available: Mapped[bool | None] = mapped_column(Boolean)
    max_bounty: Mapped[float | None] = mapped_column(Float)
    currency: Mapped[str | None] = mapped_column(String(32))
    amounts: Mapped[list] = mapped_column(JSON, default=list)
    payment_info: Mapped[str | None] = mapped_column(Text)
    severity_definitions: Mapped[list] = mapped_column(JSON, default=list)
    confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(64))
    evidence_response_id: Mapped[int | None] = mapped_column(
        ForeignKey("authorization_responses.id")
    )
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    program: Mapped[Program] = relationship(back_populates="bounty_terms")


class ResearchSession(Base):
    __tablename__ = "research_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int | None] = mapped_column(ForeignKey("programs.id"))
    asset: Mapped[str] = mapped_column(String(512))
    method: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))  # BLOCKED, STARTED, COMPLETED, FAILED
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column()
    output: Mapped[str | None] = mapped_column(Text)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    session_id: Mapped[int | None] = mapped_column(ForeignKey("research_sessions.id"))
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str | None] = mapped_column(String(32))
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="DRAFT")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    program_id: Mapped[int | None] = mapped_column(Integer, index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    kind: Mapped[str] = mapped_column(String(64))
    message: Mapped[str] = mapped_column(Text)
    program_id: Mapped[int | None] = mapped_column(Integer)
    read: Mapped[bool] = mapped_column(Boolean, default=False)


def as_utc(value: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes; everything we store is UTC."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
