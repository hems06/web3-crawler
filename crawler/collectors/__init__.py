from .base import Collector, FetchRefused, PoliteFetcher
from .bounty_targets import BountyTargetsCollector
from .defillama import DefiLlamaSecurityTxtCollector
from .hackerone import HackerOneCollector
from .program_page import ProgramPageCollector
from .security_txt import SecurityTxtCollector
from .seed import SeedCollector

REGISTRY: dict[str, type[Collector]] = {
    c.name: c
    for c in (
        SeedCollector,
        BountyTargetsCollector,
        DefiLlamaSecurityTxtCollector,
        SecurityTxtCollector,
        ProgramPageCollector,
        HackerOneCollector,
    )
}

__all__ = [
    "BountyTargetsCollector",
    "Collector",
    "DefiLlamaSecurityTxtCollector",
    "FetchRefused",
    "PoliteFetcher",
    "REGISTRY",
]
