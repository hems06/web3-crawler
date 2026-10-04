"""Celery app. Discovery and research run on separate queues; the beat
schedule only ever triggers discovery and housekeeping, never research."""

from celery import Celery
from celery.schedules import crontab

from ..config import get_settings

settings = get_settings()
app = Celery("crawler", broker=settings.redis_url, backend=settings.redis_url, include=["crawler.workers.tasks"])
app.conf.task_routes = {
    "crawler.workers.tasks.run_research": {"queue": "research"},
    "crawler.workers.tasks.*": {"queue": "discovery"},
}
app.conf.beat_schedule = {
    "discover-every-6h": {"task": "crawler.workers.tasks.discover", "schedule": crontab(minute=0, hour="*/6")},
    "expire-hourly": {"task": "crawler.workers.tasks.expire", "schedule": crontab(minute=15)},
    "inbox-every-15m": {"task": "crawler.workers.tasks.poll_inbox", "schedule": crontab(minute="*/15")},
}
