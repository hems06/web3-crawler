"""Collector base class and a polite HTTP fetcher.

Collectors only read public pages or official APIs the user has
credentials for. The fetcher honours robots.txt, identifies itself, rate
limits per host, and never follows a login wall.
"""

from __future__ import annotations

import logging
import time
from typing import Iterable
from urllib import robotparser
from urllib.parse import urlparse

import httpx

from ..config import Settings, get_settings

log = logging.getLogger("crawler.collectors")


class FetchRefused(Exception):
    pass


class PoliteFetcher:
    def __init__(self, settings: Settings | None = None, client: httpx.Client | None = None):
        self.settings = settings or get_settings()
        self.client = client or httpx.Client(
            headers={"User-Agent": self.settings.crawler_user_agent},
            timeout=20,
            follow_redirects=True,
        )
        self._robots: dict[str, robotparser.RobotFileParser | None] = {}
        self._last_hit: dict[str, float] = {}

    def _robots_for(self, url: str) -> robotparser.RobotFileParser | None:
        parts = urlparse(url)
        base = f"{parts.scheme}://{parts.netloc}"
        if base not in self._robots:
            rp = robotparser.RobotFileParser()
            try:
                resp = self.client.get(base + "/robots.txt")
                if resp.status_code >= 400:
                    rp = None  # no robots.txt: allowed
                else:
                    rp.parse(resp.text.splitlines())
            except httpx.HTTPError:
                rp = None
            self._robots[base] = rp
        return self._robots[base]

    def allowed(self, url: str) -> bool:
        rp = self._robots_for(url)
        return True if rp is None else rp.can_fetch(self.settings.crawler_user_agent, url)

    def _throttle(self, host: str) -> None:
        wait = self.settings.request_delay_seconds - (time.monotonic() - self._last_hit.get(host, 0))
        if wait > 0:
            time.sleep(wait)
        self._last_hit[host] = time.monotonic()

    def get(self, url: str, check_robots: bool = True, **kwargs) -> httpx.Response:
        if not url.startswith("https://"):
            raise FetchRefused(f"only https URLs are fetched: {url}")
        if check_robots and not self.allowed(url):
            raise FetchRefused(f"robots.txt disallows {url}")
        self._throttle(urlparse(url).netloc)
        resp = self.client.get(url, **kwargs)
        if resp.status_code in (401, 403):
            raise FetchRefused(f"{url} requires authentication ({resp.status_code}); not bypassing")
        return resp


class Collector:
    """Yields raw program dicts in the shape normalizer.normalize() expects."""

    name = "base"

    def __init__(self, settings: Settings | None = None, fetcher: PoliteFetcher | None = None):
        self.settings = settings or get_settings()
        self._fetcher = fetcher

    @property
    def fetcher(self) -> PoliteFetcher:
        if self._fetcher is None:
            self._fetcher = PoliteFetcher(self.settings)
        return self._fetcher

    def enabled(self) -> bool:
        return True

    def collect(self) -> Iterable[dict]:  # pragma: no cover - interface
        raise NotImplementedError
