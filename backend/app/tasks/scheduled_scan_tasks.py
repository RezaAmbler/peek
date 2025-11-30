from celery import Task
from datetime import datetime, timedelta
from croniter import croniter
import pytz
import logging
from ..celery_app import celery_app
from ..db.sync_session import get_sync_db
from ..models import ScheduledScan, Scan, ScanTarget
from ..models.scan import ScanStatus, ScanPhase
from ..tasks.scan_tasks import run_scan
from ..services.comparison_service import ComparisonService
import uuid
from sqlalchemy import desc

logger = logging.getLogger(__name__)

@celery_app.task(name="app.tasks.scheduled_scan_tasks.check_scheduled_scans")
def check_scheduled_scans():
    """
    Periodic task that checks for scheduled scans that need to run.
    Runs every minute via Celery Beat.
    """
    with get_sync_db() as db:
        # Get all active scheduled scans
        scheduled_scans = db.query(ScheduledScan).filter(
            ScheduledScan.is_active == True
        ).all()

        now = datetime.utcnow()

        for scheduled_scan in scheduled_scans:
            # Calculate next run time if not set
            if not scheduled_scan.next_run_at:
                scheduled_scan.next_run_at = calculate_next_run(
                    scheduled_scan.cron_expression,
                    scheduled_scan.timezone,
                    now
                )
                db.commit()
                continue

            # Check if it's time to run
            if scheduled_scan.next_run_at <= now:
                # Queue execution task
                execute_scheduled_scan.delay(str(scheduled_scan.id))

                # Update next run time
                scheduled_scan.next_run_at = calculate_next_run(
                    scheduled_scan.cron_expression,
                    scheduled_scan.timezone,
                    now
                )
                db.commit()

@celery_app.task(name="app.tasks.scheduled_scan_tasks.execute_scheduled_scan")
def execute_scheduled_scan(scheduled_scan_id: str):
    """
    Execute a scheduled scan: create scan, run it, optionally compare, send notifications.
    """
    with get_sync_db() as db:
        # Load scheduled scan
        scheduled_scan = db.query(ScheduledScan).filter(
            ScheduledScan.id == scheduled_scan_id
        ).first()

        if not scheduled_scan or not scheduled_scan.is_active:
            return

        # Create scan from schedule
        scan = Scan(
            id=str(uuid.uuid4()),
            user_id=scheduled_scan.user_id,
            created_by_id=scheduled_scan.created_by_id,
            organization_id=scheduled_scan.organization_id,
            config_id=scheduled_scan.config_id,
            name=f"{scheduled_scan.name} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}",
            description=f"Scheduled scan: {scheduled_scan.description or 'Auto-generated'}",
            status="pending",
            total_targets=len(scheduled_scan.targets)
        )
        db.add(scan)
        db.flush()

        # Create targets
        for idx, target in enumerate(scheduled_scan.targets):
            scan_target = ScanTarget(
                id=str(uuid.uuid4()),
                scan_id=str(scan.id),
                ip_address=target['ip_address'],
                device_name=target.get('device_name'),
                sequence=idx
            )
            db.add(scan_target)

        db.commit()

        # Update scheduled scan metadata
        scheduled_scan.last_run_at = datetime.utcnow()
        scheduled_scan.last_run_scan_id = str(scan.id)
        scheduled_scan.total_runs += 1
        db.commit()

        # Queue scan execution
        task = run_scan.delay(str(scan.id))
        scan.celery_task_id = task.id
        scan.status = "queued"
        db.commit()

        # Schedule post-scan tasks (comparison, notifications)
        # These will run after scan completes
        post_scan_tasks.apply_async(
            args=[str(scan.id), scheduled_scan_id],
            countdown=0  # Will check scan status periodically
        )

@celery_app.task(bind=True, max_retries=100, name="app.tasks.scheduled_scan_tasks.post_scan_tasks")
def post_scan_tasks(self, scan_id: str, scheduled_scan_id: str):
    """
    Handle post-scan tasks: comparison, notifications.
    Retries until scan completes.
    """
    with get_sync_db() as db:
        # Load scan
        scan = db.query(Scan).filter(Scan.id == scan_id).first()

        if not scan:
            return

        # Wait for scan to complete
        if scan.status in ["pending", "queued", "running"]:
            # Retry in 30 seconds
            raise self.retry(countdown=30)

        if scan.status != "completed":
            # Scan failed, no post-processing
            return

        # Load scheduled scan
        scheduled_scan = db.query(ScheduledScan).filter(
            ScheduledScan.id == scheduled_scan_id
        ).first()

        if not scheduled_scan:
            return

        comparison = None

        # Auto-comparison
        if scheduled_scan.auto_compare:
            baseline_id = None

            if scheduled_scan.compare_with_previous:
                # Compare with previous run
                # Find the scan before this one
                previous_scans = db.query(Scan).filter(
                    Scan.user_id == scheduled_scan.user_id,
                    Scan.config_id == scheduled_scan.config_id,
                    Scan.status == "completed",
                    Scan.id != scan_id,
                    Scan.created_at < scan.created_at
                ).order_by(desc(Scan.created_at)).limit(1).all()

                if previous_scans:
                    baseline_id = str(previous_scans[0].id)

            elif scheduled_scan.baseline_scan_id:
                # Compare with fixed baseline
                baseline_id = scheduled_scan.baseline_scan_id

            if baseline_id:
                # Perform comparison
                service = ComparisonService(db)
                try:
                    comparison = service.compare_scans(
                        baseline_scan_id=baseline_id,
                        current_scan_id=scan_id,
                        user_id=scheduled_scan.user_id
                    )
                except Exception as e:
                    # Log error but don't fail the task
                    print(f"Comparison failed: {str(e)}")

        # Send notifications
        if scheduled_scan.email_on_completion or scheduled_scan.email_on_changes_only:
            send_notification(scheduled_scan, scan, comparison)

def calculate_next_run(cron_expression: str, timezone_str: str, base_time: datetime = None) -> datetime:
    """Calculate the next run time based on cron expression"""
    if base_time is None:
        base_time = datetime.utcnow()

    # Convert to target timezone
    try:
        tz = pytz.timezone(timezone_str)
    except:
        tz = pytz.UTC

    # Create croniter and get next occurrence
    cron = croniter(cron_expression, base_time)
    next_run = cron.get_next(datetime)

    return next_run

def send_notification(scheduled_scan: ScheduledScan, scan: Scan, comparison=None):
    """
    Send email notification about scan completion with reports attached
    """
    # Skip if no recipients
    if not scheduled_scan.email_recipients:
        logger.info("No email recipients configured, skipping notification")
        return

    # Skip if email_on_changes_only and no changes
    if scheduled_scan.email_on_changes_only:
        if not comparison or comparison.total_changes == 0:
            logger.info("Email on changes only, but no changes detected. Skipping notification.")
            return

    # Check alert conditions
    should_send = False

    if scheduled_scan.email_on_completion:
        should_send = True

    if scheduled_scan.alert_on_critical and scan.total_vulnerabilities > 0:
        # TODO: Check for critical vulnerabilities specifically
        should_send = True

    if scheduled_scan.alert_on_new_vulns and comparison:
        if comparison.new_vulnerabilities > 0:
            should_send = True

    if not should_send and not scheduled_scan.email_on_completion:
        logger.info("No alert conditions met, skipping notification")
        return

    # Build summary stats
    summary_stats = {
        'status': scan.status,
        'total_targets': scan.total_targets,
        'total_open_ports': scan.total_open_ports,
        'total_vulnerabilities': scan.total_vulnerabilities
    }

    # Build comparison summary if available
    comparison_summary = None
    if comparison:
        comparison_summary = f"""Total Changes: {comparison.total_changes}
New Ports: {comparison.new_ports}
Closed Ports: {comparison.closed_ports}
New Vulnerabilities: {comparison.new_vulnerabilities}
Fixed Vulnerabilities: {comparison.fixed_vulnerabilities}

Severity Breakdown:
  🔥 Critical: {comparison.critical_changes}
  🔴 High: {comparison.high_changes}
  🟡 Medium: {comparison.medium_changes}
  ✅ Improvements: {comparison.positive_changes}
"""

    # Send email
    from ..services.email_service import EmailService

    logger.info(f"Sending notification to {len(scheduled_scan.email_recipients)} recipients")

    success = EmailService.send_scan_completion_email(
        recipients=scheduled_scan.email_recipients,
        scan_name=scheduled_scan.name,
        scan_id=str(scan.id),
        summary_stats=summary_stats,
        comparison_summary=comparison_summary,
        attach_reports=True  # Attach executive summary PDF
    )

    if success:
        logger.info(f"✅ Email notification sent successfully")
    else:
        logger.warning(f"⚠️ Email notification failed (check SMTP configuration)")


@celery_app.task(name="app.tasks.scheduled_scan_tasks.check_stuck_scans")
def check_stuck_scans():
    """
    Periodic task that checks for scans stuck in 'running' or 'queued' state.

    A scan is considered stuck if:
    - It's been in 'running' state for more than 4 hours (configurable)
    - It's been in 'queued' state for more than 30 minutes

    This typically happens when:
    - A Celery worker crashes mid-scan
    - A database error causes a task to fail without updating status
    - Network issues prevent task completion

    Runs every 5 minutes via Celery Beat.
    """
    # Thresholds for stuck detection
    RUNNING_STUCK_THRESHOLD_HOURS = 4
    QUEUED_STUCK_THRESHOLD_MINUTES = 30

    with get_sync_db() as db:
        now = datetime.utcnow()

        # Find scans stuck in 'running' state
        running_threshold = now - timedelta(hours=RUNNING_STUCK_THRESHOLD_HOURS)
        stuck_running = db.query(Scan).filter(
            Scan.status == ScanStatus.RUNNING.value,
            Scan.started_at < running_threshold
        ).all()

        for scan in stuck_running:
            hours_running = (now - scan.started_at).total_seconds() / 3600
            logger.warning(
                f"Scan {scan.id} ({scan.name}) stuck in 'running' state for {hours_running:.1f} hours. "
                f"Last phase: {scan.current_phase}. Marking as failed."
            )
            scan.status = ScanStatus.FAILED.value
            scan.current_phase = ScanPhase.FAILED.value
            scan.finished_at = now

        # Find scans stuck in 'queued' state
        queued_threshold = now - timedelta(minutes=QUEUED_STUCK_THRESHOLD_MINUTES)
        stuck_queued = db.query(Scan).filter(
            Scan.status == ScanStatus.QUEUED.value,
            Scan.created_at < queued_threshold
        ).all()

        for scan in stuck_queued:
            minutes_queued = (now - scan.created_at).total_seconds() / 60
            logger.warning(
                f"Scan {scan.id} ({scan.name}) stuck in 'queued' state for {minutes_queued:.0f} minutes. "
                f"Marking as failed."
            )
            scan.status = ScanStatus.FAILED.value
            scan.current_phase = ScanPhase.FAILED.value
            scan.finished_at = now

        if stuck_running or stuck_queued:
            db.commit()
            logger.info(
                f"Stuck scan detector: marked {len(stuck_running)} running + "
                f"{len(stuck_queued)} queued scans as failed"
            )
