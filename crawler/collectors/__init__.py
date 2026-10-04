from .base import Collector, FetchRefused, PoliteFetcher
from .hackerone import HackerOneCollector
from .program_page import ProgramPageCollector
from .security_txt import SecurityTxtCollector
from .seed import SeedCollector

REGISTRY: dict[str, type[Collector]] = {
    c.name: c for c in (SeedCollector, SecurityTxtCollector, ProgramPageCollector, HackerOneCollector)
}

__all__ = ["Collector", "FetchRefused", "PoliteFetcher", "REGISTRY"]
