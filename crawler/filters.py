"""Program filtering by platform, access properties and classification."""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import PlatformConfig, Settings, get_settings
from .enums import Classification

PRIVATE_CLASSES = {Classification.PRIVATE_CONFIRMED, Classification.PRIVATE_POSSIBLE}


@dataclass
class ProgramFilter:
    excluded_platforms: set[str] = field(default_factory=set)
    excluded_program_types: set[str] = field(default_factory=set)
    classifications: set[str] = field(default_factory=set)
    private_only: bool = False
    min_bounty: float = 0
    # Optional exact-match filters on the four access properties.
    platform_reputation_required: bool | None = None
    invite_required: bool | None = None
    application_required: bool | None = None
    private_program_supported: bool | None = None

    @classmethod
    def from_settings(
        cls,
        settings: Settings | None = None,
        platform_config: PlatformConfig | None = None,
        extra_exclusions: list[str] | None = None,
        **overrides,
    ) -> "ProgramFilter":
        settings = settings or get_settings()
        pc = platform_config or PlatformConfig.load(settings)
        f = cls(
            excluded_platforms=set(pc.excluded_platforms) | {e.lower() for e in extra_exclusions or []},
            excluded_program_types=set(pc.excluded_program_types),
            classifications=set(settings.program_type_filter_list),
            private_only=settings.private_only,
            min_bounty=settings.min_bounty,
        )
        for k, v in overrides.items():
            if v is not None:
                setattr(f, k, v)
        return f

    def reject_reason(self, program, platform_config: PlatformConfig) -> str | None:
        slug = program.platform.slug if hasattr(program.platform, "slug") else str(program.platform)
        if slug.lower() in self.excluded_platforms:
            return f"platform {slug} excluded"
        props = {k: getattr(program, k) for k in PlatformConfig.ACCESS_KEYS}
        tags = platform_config.program_type_tags(props) & self.excluded_program_types
        if tags:
            return f"program type excluded: {', '.join(sorted(tags))}"
        for key in PlatformConfig.ACCESS_KEYS:
            wanted = getattr(self, key)
            if wanted is not None and bool(props[key]) != wanted:
                return f"{key} != {wanted}"
        if self.classifications and program.classification not in self.classifications:
            return f"classification {program.classification} filtered"
        if self.private_only and program.classification not in PRIVATE_CLASSES:
            return "not private (PRIVATE_ONLY=true)"
        if self.min_bounty and (program.max_bounty or 0) < self.min_bounty:
            # Unknown bounty on a private program is kept: that is what the
            # authorization email asks about.
            if not (program.max_bounty is None and program.classification in PRIVATE_CLASSES):
                return f"max bounty below {self.min_bounty}"
        return None

    def apply(self, programs, platform_config: PlatformConfig | None = None):
        pc = platform_config or PlatformConfig.load()
        return [p for p in programs if self.reject_reason(p, pc) is None]
