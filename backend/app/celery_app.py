from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_ready
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
        'check-stuck-scans': {
            'task': 'app.tasks.scheduled_scan_tasks.check_stuck_scans',
            'schedule': 300.0,  # Check every 5 minutes
        },
    },
)


# How long the worker waits at startup for the API to finish migrating the schema
SCHEMA_WAIT_ATTEMPTS = 10
SCHEMA_WAIT_SECONDS = 3.0


@worker_ready.connect
def fail_scans_interrupted_by_restart(**_kwargs):
    """A worker that is just starting cannot have a scan in flight.

    Whatever is still marked "running" was cut off when the previous worker
    stopped (crash, OOM kill, redeploy). Without this such a scan sat at
    "running" until the stuck-scan detector fired hours later, with tool runs
    that never got a finished_at. Queued scans are left alone: their tasks are
    still in the broker and run normally.

    Assumes the single worker of docker-compose.yml. Set
    FAIL_RUNNING_SCANS_ON_WORKER_START=false when running several workers.
    """
    if not settings.FAIL_RUNNING_SCANS_ON_WORKER_START:
        return
    import logging
    logger = logging.getLogger(__name__)
    import time
    from sqlalchemy.exc import OperationalError
    try:
        from .db.sync_session import get_sync_db
        from .tasks.scan_tasks import fail_interrupted_scans
        # The API container applies schema migrations when it starts, and after
        # a deploy both start together: give it a moment to add new columns.
        for attempt in range(SCHEMA_WAIT_ATTEMPTS):
            try:
                with get_sync_db() as db:
                    count = fail_interrupted_scans(db, "Scan interrupted: the worker was restarted while it was running")
                break
            except OperationalError:
                if attempt == SCHEMA_WAIT_ATTEMPTS - 1:
                    raise
                time.sleep(SCHEMA_WAIT_SECONDS)
        if count:
            logger.warning(f"Marked {count} scan(s) interrupted by a worker restart as failed")
    except Exception as exc:  # never keep the worker from starting
        logger.error(f"Could not clean up interrupted scans: {exc}")
