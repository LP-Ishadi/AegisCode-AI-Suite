"""Optional queue bootstrap. Redis must be a managed TLS-enabled service."""

from celery import Celery

from app.core.config import get_settings


def create_celery_app() -> Celery:
    settings = get_settings()
    if not settings.redis_url:
        raise RuntimeError("REDIS_URL is required to start workers")
    broker = settings.redis_url.get_secret_value()
    if not broker.startswith("rediss://"):
        raise ValueError("Managed Redis must use TLS (rediss://)")
    app = Celery("aegiscode", broker=broker)
    app.conf.update(
        accept_content=["json"],
        task_serializer="json",
        result_serializer="json",
        task_ignore_result=True,
        task_track_started=False,
        worker_prefetch_multiplier=1,
        task_time_limit=300,
        task_soft_time_limit=270,
        broker_connection_retry_on_startup=True,
    )
    return app
