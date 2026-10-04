"""Programs the user curated by hand in config/seeds/*.yaml."""

from __future__ import annotations

from pathlib import Path

import yaml

from .base import Collector


class SeedCollector(Collector):
    name = "seed"

    def __init__(self, *args, paths: list[Path] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.paths = paths

    def collect(self):
        paths = self.paths or sorted((Path(self.settings.config_dir) / "seeds").glob("*.y*ml"))
        for path in paths:
            data = yaml.safe_load(Path(path).read_text()) or {}
            for entry in data.get("programs") or []:
                entry = dict(entry)
                entry.setdefault("source_url", f"file://{Path(path).name}")
                yield entry
