from celery import Celery
from celery.schedules import crontab
from .core.config import settings

celery_app = Celery(
    "peek",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.tasks.scan_tasks", "app.tasks.scheduled_scan_tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600 * 2,  # 2 hours max per task
    worker_prefetch_multiplier=1,  # Only fetch one task at a time
    worker_max_tasks_per_child=10,  # Restart worker after 10 tasks (memory cleanup)

    # Celery Beat schedule
    beat_schedule={
        'check-scheduled-scans': {
            'task': 'app.tasks.scheduled_scan_tasks.check_scheduled_scans',
            'schedule': 60.0,  # Check every minute
        },
    },
)
