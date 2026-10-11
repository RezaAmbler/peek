from celery import Task
from datetime import datetime
from typing import List, Optional
from ..celery_app import celery_app
from ..db.sync_session import get_sync_db, read_scan_status, write_scan_progress
from ..models import Scan, ScanTarget, ToolExecution, ScanStatus, ScanPhase, TargetStatus, Port
from ..tools.nmap import run_nmap, run_nmap_discovery
from ..tools.ssh_audit import run_ssh_audit
from ..tools.nuclei import run_nuclei, run_nuclei_list
from ..parsers.nmap_discovery_parser import create_ports_from_nmap_discovery
from ..parsers.nmap_parser import update_ports_from_nmap
from ..parsers.ssh_audit_parser import create_ssh_audit_from_output
from ..parsers.nuclei_parser import create_vulnerabilities_from_nuclei
from ..services.service_profile import get_nuclei_profile, build_nuclei_target, get_excluded_templates, validate_tags, determine_http_protocol
from ..core.debug import save_nmap_debug, save_nuclei_debug, save_ssh_audit_debug
from ..tools.nmap_nse import run_nmap_nse, parse_nse_output, determine_nse_severity
from ..tools.sslscan import run_sslscan, parse_sslscan_output, analyze_ssl_security, calculate_ssl_grade
from ..tools.testssl import run_testssl, check_testssl_available
from ..tools.nikto import run_nikto
from ..tools.zap import run_zap_baseline, check_zap_available
from ..tools.httpx import run_httpx, check_httpx_available, HttpxOutput
from ..tools.katana import run_katana, check_katana_available, KatanaOutput
from ..services.storage import screenshot_storage, artifact_storage
from ..services.port_classifier import get_http_candidate_ports, get_tls_candidate_ports
from ..services.url_normalizer import extract_base_url
from ..parsers.katana_parser import create_endpoints_from_katana
from ..models.discovered_endpoint import DiscoveredEndpoint
from ..services.nse_profile import get_nse_profile_service
from ..models.nse_finding import NseFinding
from ..models.sslscan_result import SslScanResult
from ..models.testssl_result import TestsslResult
from ..models.httpx_result import HttpxResult
from ..parsers.testssl_parser import parse_testssl_output, analyze_testssl_security
from ..parsers.nikto_parser import create_vulnerabilities_from_nikto
from ..parsers.zap_parser import create_vulnerabilities_from_zap
from ..parsers.httpx_parser import create_httpx_result_from_output
import math
import os
import time
import uuid
from urllib.parse import urlsplit
import logging
import tempfile
from ..tools.base import ScanCancelled, set_cancel_check, set_progress_hook
from ..core.timeutil import utcnow

logger = logging.getLogger(__name__)

# raw_output is truncated to this many characters; full output goes to artifacts
RAW_OUTPUT_LIMIT = 50000

# Single source of truth for the progress bar: (start, end) fraction per phase.
# Ranges are contiguous and ordered, and progress is only ever written through
# set_phase_progress(), which never moves it backwards.
PHASE_PROGRESS = {
    'nmap_discovery':   (0.00, 0.10),
    'nmap':             (0.10, 0.75),
    'httpx':            (0.75, 0.78),
    'katana':           (0.78, 0.80),
    'ssh-audit':        (0.80, 0.85),
    'nuclei':           (0.85, 0.88),
    'nuclei_endpoints': (0.88, 0.91),
    'nse':              (0.91, 0.93),
    'sslscan':          (0.93, 0.95),
    'testssl':          (0.95, 0.97),
    'nikto':            (0.97, 0.98),
    'zap':              (0.98, 1.00),
}


def phase_progress(phase: str, fraction: float = 0.0) -> float:
    """Overall progress (0..1) for a phase that is `fraction` (0..1) done."""
    start, end = PHASE_PROGRESS[phase]
    fraction = min(max(fraction, 0.0), 1.0)
    return round(start + (end - start) * fraction, 4)


# The step of the current phase that is running right now. The heartbeat uses
# it to move the bar inside that step's slice while a long tool run is going.
_progress_step = {"phase": None, "done": 0, "total": 1}

# Heartbeat: progress approaches (never reaches) the end of the running step.
HEARTBEAT_INTERVAL_SECONDS = 10.0
HEARTBEAT_MAX_FRACTION = 0.95
HEARTBEAT_MIN_TAU_SECONDS = 60.0


def _record_phase_step(scan: Scan, phase: str, done: int, total: int) -> None:
    _progress_step.update(phase=phase, done=done, total=max(total, 1))
    # New dict: JSON columns only detect reassignment
    scan.phase_stats = {**(scan.phase_stats or {}), phase: {"completed": done, "total": max(total, 1)}}


def begin_phase_steps(db, scan: Scan, phase: str, total: int = 1) -> None:
    """Announce that `phase` is about to run `total` steps (tool runs)."""
    _record_phase_step(scan, phase, 0, total)
    scan.progress_updated_at = utcnow()
    db.commit()


def set_phase_progress(db, scan: Scan, phase: str, done: int = 1, total: int = 1) -> None:
    """Record progress within a phase. Monotonic: never lowers scan.progress_percent."""
    fraction = (done / total) if total else 1.0
    value = phase_progress(phase, fraction)
    # The heartbeat writes progress outside this session: compare with the stored value
    stored = db.query(Scan.progress_percent).filter(Scan.id == scan.id).scalar() or 0.0
    scan.progress_percent = max(value, stored, scan.progress_percent or 0.0)
    scan.progress_updated_at = utcnow()
    _record_phase_step(scan, phase, done if total else 1, total or 1)
    db.commit()


def heartbeat_progress(elapsed: float, timeout: float) -> Optional[float]:
    """Overall progress for a tool that has been running `elapsed` seconds.

    Stays inside the slice of the step that is running, so the next
    set_phase_progress() call can only move the bar forward.
    """
    phase, done, total = _progress_step["phase"], _progress_step["done"], _progress_step["total"]
    if phase is None or done >= total:
        return None
    low = phase_progress(phase, done / total)
    high = phase_progress(phase, (done + 1) / total)
    tau = max(HEARTBEAT_MIN_TAU_SECONDS, (timeout or 0) / 4)
    fraction = HEARTBEAT_MAX_FRACTION * (1 - math.exp(-max(elapsed, 0.0) / tau))
    return round(low + (high - low) * fraction, 4)


def make_progress_heartbeat(scan_id: str, min_interval: float = HEARTBEAT_INTERVAL_SECONDS):
    """Callable for tools.base.set_progress_hook: keeps the bar moving during a long tool run."""
    state = {"at": 0.0}

    def beat(elapsed: float, timeout: float) -> None:
        now = time.monotonic()
        if now - state["at"] < min_interval:
            return
        state["at"] = now
        value = heartbeat_progress(elapsed, timeout)
        if value is not None:
            write_scan_progress(scan_id, value)

    return beat


def _truncate(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    return raw[:RAW_OUTPUT_LIMIT]


def start_tool_exec(db, target: ScanTarget, tool_name: str, port_rec=None,
                    command_line: Optional[str] = None) -> ToolExecution:
    """Create and commit the ToolExecution row for a run that is about to start.

    Committed (not just flushed) so that a later rollback in an error handler
    cannot make the row disappear: a run that blows up is still recorded.
    """
    tool_exec = ToolExecution(
        id=str(uuid.uuid4()),
        scan_target_id=str(target.id),
        port_id=str(port_rec.id) if port_rec is not None else None,
        tool_name=tool_name,
        command_line=command_line,
        started_at=utcnow()
    )
    db.add(tool_exec)
    db.commit()
    return tool_exec


def record_tool_result(tool_exec: ToolExecution, result, raw_output: Optional[str] = None,
                       raw_format: Optional[str] = None) -> None:
    """Copy a runner result (ToolResult or *Output dataclass) onto the ToolExecution.

    Stores the real exit code and the exact command line the runner executed.
    A failed run always carries an error_message.
    """
    tool_exec.finished_at = utcnow()
    tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
    tool_exec.raw_output = raw_output if raw_output else None
    if raw_format:
        tool_exec.raw_format = raw_format
    command_line = getattr(result, 'command_line', None)
    if command_line:
        tool_exec.command_line = command_line
    exit_code = getattr(result, 'exit_code', None)
    if exit_code is None:
        exit_code = 0 if result.success else 1
    tool_exec.exit_code = exit_code
    error = result.error
    if not result.success and not error:
        error = f"{tool_exec.tool_name} failed (exit code {exit_code})"
    tool_exec.error_message = error
    # Plain attribute (not a mapped column): survives the expiry that follows a
    # failed flush, so fail_tool_exec() can still store what the tool produced.
    tool_exec._runner_snapshot = {
        'raw_output': tool_exec.raw_output,
        'raw_format': tool_exec.raw_format,
        'command_line': tool_exec.command_line,
        'exit_code': exit_code,
    }


def fail_tool_exec(db, tool_exec: Optional[ToolExecution], exc: BaseException) -> None:
    """Finalize a ToolExecution after an unexpected exception in its phase.

    Rolls the session back first (it may be in a failed-flush state, in which
    case any further commit would raise PendingRollbackError), then records the
    failure with timing and whatever output had already been captured.
    """
    # A failed flush expires the mapped attributes, so what the runner returned
    # is taken from the plain-Python snapshot kept by record_tool_result().
    pending = dict(getattr(tool_exec, '_runner_snapshot', None) or {})
    try:
        db.rollback()
    except Exception as rollback_err:  # pragma: no cover - defensive
        logger.error(f"Session rollback failed: {rollback_err}")
    if tool_exec is None:
        return
    try:
        for attr in ('raw_output', 'raw_format', 'command_line'):
            value = pending.get(attr)
            if value is not None:
                setattr(tool_exec, attr, _truncate(value) if attr == 'raw_output' else value)
        tool_exec.finished_at = utcnow()
        tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
        tool_exec.error_message = f"{type(exc).__name__}: {exc}"[:2000]
        # Keep the tool's own non-zero exit code if it had one; otherwise 1
        tool_exec.exit_code = pending.get('exit_code') or 1
        db.commit()
    except Exception as finalize_err:
        logger.error(f"Could not finalize ToolExecution after error: {finalize_err}")
        db.rollback()


def fail_unfinished_tool_execs(db, scan_id: str, reason: str) -> int:
    """Mark every ToolExecution of the scan that never finished as failed."""
    unfinished = db.query(ToolExecution).join(ScanTarget).filter(
        ScanTarget.scan_id == str(scan_id),
        ToolExecution.finished_at.is_(None)
    ).all()
    now = utcnow()
    for tool_exec in unfinished:
        tool_exec.finished_at = now
        if tool_exec.started_at:
            tool_exec.duration_ms = int((now - tool_exec.started_at).total_seconds() * 1000)
        tool_exec.exit_code = tool_exec.exit_code or 1
        tool_exec.error_message = tool_exec.error_message or reason[:2000]
    return len(unfinished)


# Minimum seconds between two status reads made on behalf of a running tool.
CANCEL_CHECK_INTERVAL_SECONDS = 5.0


def make_cancel_check(scan_id: str, min_interval: float = CANCEL_CHECK_INTERVAL_SECONDS):
    """Callable for tools.base.set_cancel_check: True once the scan is cancelled.

    `POST /api/scans/{id}/cancel` only writes status=cancelled; this is how the
    worker notices. A deleted scan counts as cancelled too.
    """
    state = {"checked_at": 0.0, "cancelled": False}

    def check(force: bool = False) -> bool:
        now = time.monotonic()
        if state["cancelled"] or (not force and now - state["checked_at"] < min_interval):
            return state["cancelled"]
        state["checked_at"] = now
        status = read_scan_status(scan_id)
        state["cancelled"] = status is None or status == ScanStatus.CANCELLED.value
        return state["cancelled"]

    return check


def mark_scan_failed(db, scan: Scan, reason: str, now=None) -> None:
    """Set a scan to failed and record why. The caller commits.

    Target counters are normally written when a scan completes; a failed scan
    gets them too, so the UI does not show "0 failed" for a scan that died.
    Targets that never finished count as failed.
    """
    now = now or utcnow()
    scan.status = ScanStatus.FAILED.value
    scan.current_phase = ScanPhase.FAILED.value
    scan.finished_at = now
    scan.error_message = (reason or "Scan failed")[:2000]

    for target in db.query(ScanTarget).filter(ScanTarget.scan_id == scan.id).all():
        if target.status in (TargetStatus.PENDING.value, TargetStatus.SCANNING.value):
            target.status = TargetStatus.FAILED.value
            target.error_message = target.error_message or scan.error_message
            target.finished_at = target.finished_at or now
    db.flush()
    scan.completed_targets = db.query(ScanTarget).filter(
        ScanTarget.scan_id == scan.id,
        ScanTarget.status == TargetStatus.COMPLETED.value
    ).count()
    scan.failed_targets = db.query(ScanTarget).filter(
        ScanTarget.scan_id == scan.id,
        ScanTarget.status.in_([TargetStatus.FAILED.value, TargetStatus.TIMEOUT.value])
    ).count()


def finish_cancelled_scan(db, scan_id: str) -> None:
    """Close out a scan that was cancelled: no tool run stays open, status stays cancelled."""
    db.rollback()
    try:
        fail_unfinished_tool_execs(db, scan_id, "Scan cancelled")
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.CANCELLED.value
            if not scan.finished_at:
                scan.finished_at = utcnow()
        db.commit()
    except Exception as finalize_err:
        logger.error(f"Could not finalize cancelled scan {scan_id}: {finalize_err}")
        db.rollback()


def fail_interrupted_scans(db, reason: str) -> int:
    """Fail every scan still marked running and close its open tool runs.

    Called when the worker starts: a scan cannot survive the worker that was
    running it, so anything still "running" at that point was interrupted.
    """
    interrupted = db.query(Scan).filter(Scan.status == ScanStatus.RUNNING.value).all()
    now = utcnow()
    for scan in interrupted:
        fail_unfinished_tool_execs(db, scan.id, reason)
        mark_scan_failed(db, scan, reason, now)
    # Cancelled scans whose worker died before it could close them out
    for scan in db.query(Scan).filter(Scan.status == ScanStatus.CANCELLED.value).all():
        closed = fail_unfinished_tool_execs(db, scan.id, "Scan cancelled")
        if closed or not scan.finished_at:
            scan.finished_at = scan.finished_at or now
    db.commit()
    return len(interrupted)



class DatabaseTask(Task):
    """Base task with database session"""
    _db = None

    @property
    def db(self):
        if self._db is None:
            raise RuntimeError("Database session not initialized")
        return self._db

@celery_app.task(bind=True, base=DatabaseTask, name="app.tasks.scan_tasks.run_scan")
def run_scan(self, scan_id: str):
    """
    Main scan orchestrator.

    Progress ranges come from PHASE_PROGRESS (the single source of truth):

    Phase 1: Port Discovery (0% -> 10%)
    Phase 2: Nmap Service Detection (10% -> 75%)
    Phase 3: httpx HTTP Probing (75% -> 78%)
    Phase 3.5: Katana Endpoint Discovery (78% -> 80%)
    Phase 4: SSH-Audit (80% -> 85%)
    Phase 5: Nuclei per-port (85% -> 88%)
    Phase 5.5: Nuclei endpoint-mode (88% -> 91%)
    Phase 6: NSE Scripts (91% -> 93%)
    Phase 7: SSLScan (93% -> 95%)
    Phase 7.5: testssl.sh Deep TLS Analysis (95% -> 97%)
    Phase 8: Nikto (97% -> 98%)
    Phase 9: ZAP (98% -> 100%)
    """
    with get_sync_db() as db:
        self._db = db

        # Load scan
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        # Load config
        from ..models import ScanConfig
        config = db.query(ScanConfig).filter(ScanConfig.id == scan.config_id).first()
        if not config:
            raise ValueError(f"Config {scan.config_id} not found")

        # Cancelled while it was still waiting in the queue: nothing to run
        if scan.status == ScanStatus.CANCELLED.value:
            logger.info(f"Scan {scan_id} was cancelled before it started")
            finish_cancelled_scan(db, scan_id)
            return

        # Update scan status
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = utcnow()
        scan.current_phase = ScanPhase.NMAP_DISCOVERY.value
        db.commit()

        # Running tools poll this (tools.base.run_command); phases check it too
        cancel_check = make_cancel_check(scan_id)
        set_cancel_check(cancel_check)
        set_progress_hook(make_progress_heartbeat(scan_id))
        _progress_step.update(phase=None, done=0, total=1)

        def stop_if_cancelled():
            if cancel_check(force=True):
                raise ScanCancelled(f"scan {scan_id} cancelled")

        try:
            # Load targets
            targets = db.query(ScanTarget).filter(
                ScanTarget.scan_id == scan_id
            ).order_by(ScanTarget.sequence).all()

            # Phase 1: Port Discovery (0% -> 10%)
            self.update_state(state='PROGRESS', meta={'phase': 'nmap_discovery', 'progress': phase_progress('nmap_discovery')})
            run_masscan_phase(db, scan, targets, config)

            # Update total_open_ports after discovery phase completes
            total_ports = db.query(Port).join(ScanTarget).filter(
                ScanTarget.scan_id == scan_id
            ).count()
            scan.total_open_ports = total_ports
            db.commit()

            # Phase 2: Nmap (10% -> 75%)
            stop_if_cancelled()
            scan.current_phase = ScanPhase.NMAP.value
            db.commit()
            self.update_state(state='PROGRESS', meta={'phase': 'nmap', 'progress': phase_progress('nmap')})
            run_nmap_phase(db, scan, targets, config)

            # Phase 3: httpx HTTP probing (75% -> 78%)
            if getattr(config, 'enable_httpx', True):
                stop_if_cancelled()
                scan.current_phase = ScanPhase.HTTPX.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'httpx', 'progress': phase_progress('httpx')})
                run_httpx_phase(db, scan, targets, config)

            # Phase 3.5: Katana endpoint discovery (78% -> 80%)
            if getattr(config, 'enable_katana', False):
                stop_if_cancelled()
                scan.current_phase = ScanPhase.KATANA.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'katana', 'progress': phase_progress('katana')})
                run_katana_phase(db, scan, targets, config)

            # Phase 4: SSH-Audit (80% -> 85%)
            if config.enable_ssh_audit:
                stop_if_cancelled()
                scan.current_phase = ScanPhase.SSH_AUDIT.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'ssh-audit', 'progress': phase_progress('ssh-audit')})
                run_ssh_audit_phase(db, scan, targets, config)

            # Phase 5: Nuclei per-port (85% -> 88%)
            if config.enable_nuclei:
                stop_if_cancelled()
                scan.current_phase = ScanPhase.NUCLEI.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'nuclei', 'progress': phase_progress('nuclei')})
                run_nuclei_phase(db, scan, targets, config)

            # Phase 5.5: Nuclei endpoint-mode (88% -> 91%)
            # Scans discovered endpoints from Katana
            if getattr(config, 'enable_nuclei_endpoints', False):
                stop_if_cancelled()
                scan.current_phase = ScanPhase.NUCLEI_ENDPOINTS.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'nuclei_endpoints', 'progress': phase_progress('nuclei_endpoints')})
                run_nuclei_endpoints_phase(db, scan, targets, config)

            # Phase 6: NSE Scripts (91% -> 93%)
            # NSE runs after nmap service detection to get detailed service info
            if getattr(config, 'enable_nse', True):
                stop_if_cancelled()
                scan.current_phase = ScanPhase.NSE.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'nse', 'progress': phase_progress('nse')})
                run_nse_phase(db, scan, targets, config)

            # Phase 7: sslscan (93% -> 95%)
            # sslscan runs on SSL/TLS ports for TLS posture analysis
            if getattr(config, 'enable_sslscan', True):
                stop_if_cancelled()
                scan.current_phase = ScanPhase.SSLSCAN.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'sslscan', 'progress': phase_progress('sslscan')})
                run_sslscan_phase(db, scan, targets, config)

            # Phase 7.5: testssl.sh (95% -> 97%)
            # Deep TLS analysis with testssl.sh (more comprehensive than sslscan)
            if getattr(config, 'enable_testssl', False):
                stop_if_cancelled()
                scan.current_phase = ScanPhase.TESTSSL.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'testssl', 'progress': phase_progress('testssl')})
                run_testssl_phase(db, scan, targets, config)

            # Phase 8: Nikto (97% -> 98%)
            if config.enable_nikto:
                stop_if_cancelled()
                scan.current_phase = ScanPhase.NIKTO.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'nikto', 'progress': phase_progress('nikto')})
                run_nikto_phase(db, scan, targets, config)

            # Phase 9: ZAP (98% -> 100%)
            if config.enable_zap:
                stop_if_cancelled()
                scan.current_phase = ScanPhase.ZAP.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'zap', 'progress': phase_progress('zap')})
                run_zap_phase(db, scan, targets, config)

            # Mark scan as completed (unless it was cancelled during the last phase)
            stop_if_cancelled()
            scan.status = ScanStatus.COMPLETED.value
            scan.current_phase = ScanPhase.COMPLETED.value
            scan.finished_at = utcnow()
            scan.progress_percent = 1.0

            # Update statistics
            completed = db.query(ScanTarget).filter(
                ScanTarget.scan_id == scan_id,
                ScanTarget.status == TargetStatus.COMPLETED.value
            ).count()

            failed = db.query(ScanTarget).filter(
                ScanTarget.scan_id == scan_id,
                ScanTarget.status.in_([TargetStatus.FAILED.value, TargetStatus.TIMEOUT.value])
            ).count()

            total_ports = db.query(Port).join(ScanTarget).filter(
                ScanTarget.scan_id == scan_id
            ).count()

            scan.completed_targets = completed
            scan.failed_targets = failed
            scan.total_open_ports = total_ports

            db.commit()

            # Risk enrichment: resolve CVE identity + CVSS/EPSS/KEV and compute a
            # risk_score for every finding now that the scan is complete. This runs
            # for EVERY completed scan (not just scheduled). Scheduled post_scan
            # notifications run AFTER this (they retry until status==completed), so
            # alerts can already see kev_flag/risk_score. Wrapped so an enrichment
            # failure only logs and never fails the scan.
            try:
                from ..services.enrichment_service import enrich_scan
                enrich_scan(db, scan_id)
            except Exception as enrich_err:
                logger.warning(
                    f"Risk enrichment failed for scan {scan_id} (non-fatal): {enrich_err}",
                    exc_info=True,
                )

            # Cross-scan triage memory: upsert a FindingState for every finding so
            # a "false positive"/"risk accepted" decision made in a prior run is
            # carried forward and this scan's findings become triageable. Runs
            # right after enrichment so cve_id/name are already resolved. Wrapped
            # so a failure only logs and never fails the scan.
            try:
                from ..services.finding_state_service import upsert_finding_states
                upsert_finding_states(db, scan_id)
            except Exception as state_err:
                logger.warning(
                    f"FindingState upsert failed for scan {scan_id} (non-fatal): {state_err}",
                    exc_info=True,
                )

        except ScanCancelled:
            logger.info(f"Scan {scan_id} cancelled; stopping")
            finish_cancelled_scan(db, scan_id)
            return

        except Exception as e:
            # The session may be in a failed-flush state: roll back before
            # writing, otherwise the commit below raises PendingRollbackError
            # and the scan stays RUNNING forever.
            db.rollback()
            try:
                reason = f"Scan aborted: {type(e).__name__}: {e}"
                fail_unfinished_tool_execs(db, scan_id, reason)
                mark_scan_failed(db, scan, reason)
                db.commit()
            except Exception as finalize_err:
                logger.error(f"Could not mark scan {scan_id} as failed: {finalize_err}")
                db.rollback()
            raise

        finally:
            set_cancel_check(None)
            set_progress_hook(None)

def run_masscan_phase(db, scan: Scan, targets: List[ScanTarget], config):
    """
    Run port discovery on all targets sequentially.

    Note: We use nmap for port discovery instead of masscan because masscan
    has reliability issues in Docker environments (SYN packets don't receive
    responses reliably with bridge networking).

    For SQLite backends, we process targets sequentially.
    """
    total = len(targets)
    begin_phase_steps(db, scan, 'nmap_discovery', total)
    completed = 0

    for target in targets:
        try:
            # Run nmap discovery for this target (uses same db session)
            scan_target_with_nmap_discovery(db, target, config)
        except Exception as e:
            # Log error but continue with the next target
            logger.error(f"Port discovery failed for target {target.ip_address}: {e}")
            db.rollback()
            fail_unfinished_tool_execs(db, scan.id, f"Port discovery aborted: {type(e).__name__}: {e}")
            target.status = TargetStatus.FAILED.value
            target.error_message = str(e)[:2000]
            target.finished_at = utcnow()
            db.commit()

        completed += 1

        set_phase_progress(db, scan, 'nmap_discovery', completed, total)

def scan_target_with_nmap_discovery(db, target: ScanTarget, config):
    """Execute nmap discovery for a single target using the provided db session."""
    target.status = TargetStatus.SCANNING.value
    target.started_at = utcnow()
    db.commit()

    # Use discovery timeout (shorter than full nmap service scan)
    timeout = int(config.host_timeout_seconds * config.masscan_timeout_percent)
    if config.global_tool_timeout_seconds:
        timeout = config.global_tool_timeout_seconds

    tool_exec = start_tool_exec(db, target, "nmap-discovery")

    # Use nmap discovery with config-based port strategy
    # scan_mode='deep' uses full port scan, 'fast' uses top-ports + additional
    scan_mode = getattr(config, 'scan_mode', None) or 'fast'
    full_scan = scan_mode == 'deep'

    # Calculate timeout based on scan mode
    # Full scan needs longer timeout (30 min), top-ports is faster (10 min)
    discovery_timeout = 1800 if full_scan else 600
    if getattr(config, 'global_tool_timeout_seconds', None):
        discovery_timeout = config.global_tool_timeout_seconds

    # Get port discovery settings with defaults
    top_ports = getattr(config, 'discovery_top_ports', None) or 1000
    additional_ports = getattr(config, 'additional_ports', None) or "5432,6379,11211,9200,27017,1433,1521,5984,9042,2375,2376,5672,15672,8080,8443,9000"

    result = run_nmap_discovery(
        ip=target.ip_address,
        timing_template="T4",  # Fast timing
        timeout=discovery_timeout,
        top_ports=top_ports,
        additional_ports=additional_ports,
        full_scan=full_scan
    )
    success, raw_xml, error = result

    # Save debug output (only when DEBUG=True)
    # Get scan_id from target's relationship
    scan_id = target.scan_id if hasattr(target, 'scan_id') else None
    save_nmap_debug(
        target=target.ip_address,
        raw_xml=raw_xml,
        scan_id=str(scan_id) if scan_id else None,
        phase="discovery"
    )

    record_tool_result(tool_exec, result, raw_output=raw_xml, raw_format="xml")

    if success:
        create_ports_from_nmap_discovery(db, tool_exec, target)

    if success and not tool_exec.error_message:
        target.status = TargetStatus.COMPLETED.value
    else:
        # Tool failure or unparseable output: never a "0 open ports" result
        target.status = TargetStatus.FAILED.value
        target.error_message = tool_exec.error_message

    target.finished_at = utcnow()
    target.duration_seconds = (target.finished_at - target.started_at).total_seconds()
    db.commit()


def run_nmap_phase(db, scan: Scan, targets: List[ScanTarget], config):
    """
    Run nmap on all targets with open ports sequentially.

    Masscan → Nmap handoff:
    1. Query ports discovered by masscan for each target
    2. Only run nmap if target has open ports
    3. Pass port list to nmap (scans only those ports, not all 65535)

    Note: Using sequential execution for SQLite compatibility.
    """
    # Get targets that have open ports
    targets_with_ports = []
    for target in targets:
        port_count = db.query(Port).filter(
            Port.scan_target_id == str(target.id),
            Port.state == 'open'
        ).count()

        if port_count > 0:
            targets_with_ports.append(target)

    if not targets_with_ports:
        # No open ports found, skip nmap
        set_phase_progress(db, scan, 'nmap')
        return

    total = len(targets_with_ports)
    begin_phase_steps(db, scan, 'nmap', total)
    completed = 0

    for target in targets_with_ports:
        try:
            scan_target_with_nmap_sequential(db, target, config)
        except Exception as e:
            # Nmap failure doesn't fail the scan, but we log the error
            logger.warning(f"Nmap service detection failed for target {target.ip_address}: {e}")
            db.rollback()
            fail_unfinished_tool_execs(db, scan.id, f"Nmap aborted: {type(e).__name__}: {e}")
            target.error_message = f"Nmap failed: {str(e)[:200]}"
            db.commit()

        completed += 1

        set_phase_progress(db, scan, 'nmap', completed, total)

def scan_target_with_nmap_sequential(db, target: ScanTarget, config):
    """Execute nmap for a single target using the provided db session."""
    # Get open ports
    ports = db.query(Port).filter(
        Port.scan_target_id == str(target.id),
        Port.state == 'open'
    ).all()

    port_numbers = [p.port for p in ports]

    timeout = int(config.host_timeout_seconds * config.nmap_timeout_percent)
    if config.global_tool_timeout_seconds:
        timeout = config.global_tool_timeout_seconds

    tool_exec = start_tool_exec(db, target, "nmap")

    result = run_nmap(
        ip=target.ip_address,
        ports=port_numbers,
        nmap_args=config.nmap_args,
        timeout=timeout
    )
    success, raw_xml, error = result

    record_tool_result(tool_exec, result, raw_output=raw_xml, raw_format="xml")

    if success:
        update_ports_from_nmap(db, tool_exec, target)
    else:
        logger.warning(f"Nmap service detection failed for {target.ip_address}: {error}")
        target.error_message = f"Nmap failed: {(error or '')[:200]}"

    db.commit()


def run_httpx_phase(db, scan: Scan, targets: List[ScanTarget], config):
    """
    Run httpx HTTP probing on discovered HTTP/HTTPS ports.

    This phase:
    1. Probes HTTP ports to gather rich metadata (status, title, headers)
    2. Detects technologies for enhanced nuclei scanning
    3. Validates which ports are actually serving HTTP
    4. Captures screenshots (opt-in via config.httpx_screenshots)
    5. Discovers virtual hosts (config.httpx_vhost_discovery)
    """
    logger.info(f"Starting httpx phase for scan {scan.id}")

    # Check if httpx is available
    if not check_httpx_available():
        logger.warning("httpx not available, skipping phase")
        return

    # HTTP services and common HTTP ports
    http_services = ['http', 'https', 'ssl/http', 'http-proxy', 'http-alt']
    http_port_numbers = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

    # Get HTTP-like ports (by service name OR port number)
    http_ports = db.query(Port).join(ScanTarget).filter(
        ScanTarget.scan_id == str(scan.id),
        Port.state == 'open'
    ).filter(
        (Port.service_name.in_(http_services)) |
        (Port.port.in_(http_port_numbers))
    ).all()

    if not http_ports:
        logger.info("No HTTP ports found for httpx probing")
        return

    logger.info(f"httpx: {len(http_ports)} HTTP port(s) to probe")

    # Get config options
    timeout = getattr(config, 'httpx_timeout', 30) or 30
    retries = getattr(config, 'httpx_retries', 2)  # Default 2 retries for transient failures
    tech_detect = getattr(config, 'httpx_tech_detect', True)
    screenshots_enabled = getattr(config, 'httpx_screenshots', False)
    screenshot_timeout = getattr(config, 'httpx_screenshot_timeout', 10) or 10
    vhost_discovery = getattr(config, 'httpx_vhost_discovery', True)

    if screenshots_enabled:
        logger.info(f"httpx: Screenshots enabled (timeout={screenshot_timeout}s)")
    if vhost_discovery:
        logger.info("httpx: Virtual host discovery enabled")

    total = len(http_ports)
    begin_phase_steps(db, scan, 'httpx', total)
    completed = 0

    for port_rec in http_ports:
        # Get target for this port
        target = db.query(ScanTarget).filter(
            ScanTarget.id == port_rec.scan_target_id
        ).first()

        if not target:
            completed += 1
            continue

        ip = target.ip_address
        port = port_rec.port

        # Determine protocol based on service or port
        is_ssl = (
            'ssl' in (port_rec.service_name or '') or
            'https' in (port_rec.service_name or '') or
            port in [443, 8443]
        )
        scheme = "https" if is_ssl else "http"
        target_url = f"{scheme}://{ip}:{port}"

        logger.info(f"httpx: Probing {target_url}")

        # Create tool execution record (the exact command line is filled in
        # from the runner once it has run)
        tool_exec = start_tool_exec(db, target, "httpx", port_rec,
                                    command_line=f"httpx -u {target_url} -json")

        output: Optional[HttpxOutput] = None
        try:
            # Run httpx with new options
            output: HttpxOutput = run_httpx(
                target=target_url,
                timeout=timeout,
                retries=retries,
                tech_detect=tech_detect,
                screenshots=screenshots_enabled,
                screenshot_timeout=screenshot_timeout,
                vhost_discovery=vhost_discovery
            )

            # Full output first: the parser reads tool_exec.raw_output
            record_tool_result(tool_exec, output, raw_output=output.raw_json, raw_format="json")

            if output.success and output.raw_json:
                # Parse and create HttpxResult
                result = create_httpx_result_from_output(db, tool_exec, target, port_rec)
                tool_exec.raw_output = _truncate(output.raw_json)
                if result:
                    logger.info(f"httpx: {target_url} -> {result.status_code} {result.title or ''} techs={result.technologies}")

                    # Save screenshot if captured
                    if output.screenshot_path and output.screenshot_path.exists():
                        screenshot_rel_path = screenshot_storage.save_screenshot(
                            scan_id=str(scan.id),
                            port_id=str(port_rec.id),
                            source_path=output.screenshot_path
                        )
                        if screenshot_rel_path:
                            result.screenshot_path = screenshot_rel_path
                            logger.info(f"httpx: Saved screenshot for {target_url}")

                    # Log virtual hosts if discovered
                    if isinstance(result.virtual_hosts, list) and result.virtual_hosts:
                        logger.info(f"httpx: Discovered {len(result.virtual_hosts)} virtual host(s) for {target_url}")
            else:
                # Create failed result
                tool_exec.raw_output = _truncate(output.raw_json)
                failed_result = HttpxResult(
                    id=str(uuid.uuid4()),
                    port_id=str(port_rec.id),
                    tool_execution_id=str(tool_exec.id),
                    connection_failed=True,
                    failure_reason=output.error or "Unknown error"
                )
                db.add(failed_result)

            db.commit()

        except Exception as e:
            logger.error(f"httpx error for {target_url}: {e}")
            fail_tool_exec(db, tool_exec, e)
        finally:
            # Remove the runner's temp directory (screenshot already copied)
            if output is not None:
                output.cleanup()

        completed += 1

        set_phase_progress(db, scan, 'httpx', completed, total)

    logger.info(f"httpx complete: {completed} ports probed")


def run_katana_phase(db, scan: Scan, targets: List[ScanTarget], config):
    """
    Run Katana web crawler for endpoint discovery on HTTP ports.

    This phase:
    1. Gets HTTP candidate ports from port_classifier
    2. For each HTTP port, extracts base URL from httpx results
    3. Crawls the target to discover endpoints (paths, forms, APIs)
    4. Creates DiscoveredEndpoint records for each discovered URL
    5. Stores full output in artifact storage
    """
    logger.info(f"Starting Katana phase for scan {scan.id}")

    # Check if Katana is available
    if not check_katana_available():
        logger.warning("Katana not available, skipping endpoint discovery phase")
        return

    # Get HTTP candidate ports using port_classifier
    http_ports = get_http_candidate_ports(db, str(scan.id))

    if not http_ports:
        logger.info("No HTTP ports found for Katana crawling")
        return

    logger.info(f"Katana: {len(http_ports)} HTTP port(s) to crawl")

    # Get config options with defaults
    max_depth = getattr(config, 'katana_max_depth', 2) or 2
    timeout = getattr(config, 'katana_timeout', 120) or 120
    concurrency = getattr(config, 'katana_concurrency', 10) or 10
    rate_limit = getattr(config, 'katana_rate_limit', 150) or 150
    max_endpoints = getattr(config, 'katana_max_endpoints', 500) or 500

    total = len(http_ports)
    begin_phase_steps(db, scan, 'katana', total)
    completed = 0
    total_endpoints = 0

    for port_rec in http_ports:
        # Get target for this port
        target = db.query(ScanTarget).filter(
            ScanTarget.id == port_rec.scan_target_id
        ).first()

        if not target:
            completed += 1
            continue

        ip = target.ip_address
        port = port_rec.port

        # Get httpx result for this port to determine base URL
        httpx_result = db.query(HttpxResult).filter(
            HttpxResult.port_id == str(port_rec.id)
        ).first()

        # Build target URL using httpx result or service detection
        if httpx_result and httpx_result.final_url:
            # Use httpx-discovered URL as base
            target_url = extract_base_url(httpx_result.final_url)
        else:
            # Fall back to service-based detection
            is_ssl = (
                'ssl' in (port_rec.service_name or '') or
                'https' in (port_rec.service_name or '') or
                port in [443, 8443]
            )
            scheme = "https" if is_ssl else "http"
            target_url = f"{scheme}://{ip}:{port}"

        logger.info(f"Katana: Crawling {target_url} (depth={max_depth}, timeout={timeout}s)")

        # Create tool execution record (exact command line comes from the runner)
        tool_exec = start_tool_exec(db, target, "katana", port_rec,
                                    command_line=f"katana -u {target_url} -jsonl")

        try:
            # Run Katana
            output: KatanaOutput = run_katana(
                target_url=target_url,
                depth=max_depth,
                timeout=timeout,
                concurrency=concurrency,
                rate_limit=rate_limit,
                max_endpoints=max_endpoints,
                headless=False  # Standard mode, not headless browser
            )

            record_tool_result(tool_exec, output, raw_output=_truncate(output.raw_output), raw_format="jsonl")

            # Save full raw output to artifact storage
            if output.raw_output:
                artifact_path = artifact_storage.save_artifact(
                    scan_id=str(scan.id),
                    tool_execution_id=str(tool_exec.id),
                    content=output.raw_output,
                    extension="jsonl"
                )
                if artifact_path:
                    tool_exec.artifact_path = artifact_path
                    logger.debug(f"Katana: Saved artifact to {artifact_path}")

            if output.endpoints:
                # Endpoints are kept even from a failed/timed-out crawl (partial
                # results); the ToolExecution still records the failure.
                # Parse and create DiscoveredEndpoint records
                endpoints = create_endpoints_from_katana(
                    db=db,
                    katana_output=output,
                    scan=scan,
                    target=target,
                    port_rec=port_rec,
                    tool_execution=tool_exec
                )
                total_endpoints += len(endpoints)
                logger.info(f"Katana: Discovered {len(endpoints)} endpoint(s) from {target_url}")
            elif output.success:
                logger.info(f"Katana: No endpoints discovered from {target_url}")

            if not output.success:
                logger.warning(f"Katana crawl failed for {target_url}: {output.error}")

            db.commit()

        except Exception as e:
            logger.error(f"Katana error for {target_url}: {e}")
            fail_tool_exec(db, tool_exec, e)

        completed += 1

        set_phase_progress(db, scan, 'katana', completed, total)

    logger.info(f"Katana complete: {completed} ports crawled, {total_endpoints} total endpoints discovered")


def run_ssh_audit_phase(db, scan: Scan, targets: List[ScanTarget], config):
    """
    Run ssh-audit on all SSH ports discovered.

    Queries for ports where service_name='ssh' and runs ssh-audit on configured SSH ports.
    """
    # Get all SSH ports from config (default: [22, 830])
    ssh_ports = config.ssh_ports or [22, 830]

    # Find all ports running SSH service
    ssh_port_records = db.query(Port).join(ScanTarget).filter(
        ScanTarget.scan_id == str(scan.id),
        Port.service_name == 'ssh',
        Port.port.in_(ssh_ports)
    ).all()

    if not ssh_port_records:
        # No SSH ports found, skip phase
        set_phase_progress(db, scan, 'ssh-audit')
        return

    total = len(ssh_port_records)
    begin_phase_steps(db, scan, 'ssh-audit', total)
    completed = 0

    # SSH-audit is fast, so we can run serially or in small batches
    # For simplicity, run serially (parallel would be similar to nmap)
    for port_record in ssh_port_records:
        # Get target for this port
        target = db.query(ScanTarget).filter(
            ScanTarget.id == port_record.scan_target_id
        ).first()

        if not target:
            completed += 1
            continue

        tool_exec = start_tool_exec(db, target, "ssh-audit", port_record)

        try:
            # Run ssh-audit
            # Use 60s timeout (ssh-audit is usually fast)
            timeout = 60
            if config.global_tool_timeout_seconds:
                timeout = config.global_tool_timeout_seconds

            result = run_ssh_audit(
                ip=target.ip_address,
                port=port_record.port,
                timeout=timeout
            )
            success, raw_json, error = result

            # Save debug output (only when DEBUG=True)
            save_ssh_audit_debug(
                target=target.ip_address,
                raw_json=raw_json,
                scan_id=str(scan.id),
                port=port_record.port
            )

            record_tool_result(tool_exec, result, raw_output=raw_json, raw_format="json")

            if success:
                # Parse and create SSHAudit record
                create_ssh_audit_from_output(db, tool_exec, port_record)
            else:
                # Create failed audit record
                from ..models import SSHAudit
                failed_audit = SSHAudit(
                    id=str(uuid.uuid4()),
                    port_id=str(port_record.id),
                    tool_execution_id=str(tool_exec.id),
                    connection_failed=True,
                    failure_reason=error
                )
                db.add(failed_audit)

            db.commit()

        except Exception as e:
            logger.error(f"ssh-audit error for {target.ip_address}:{port_record.port}: {e}")
            fail_tool_exec(db, tool_exec, e)

        completed += 1

        set_phase_progress(db, scan, 'ssh-audit', completed, total)

def run_nuclei_phase(db, scan: Scan, targets: List[ScanTarget], config):
    """
    Run Nuclei with service-aware template selection.

    Scans ALL open ports using service-specific templates based on
    nmap service detection. Uses nuclei_profiles.yaml for configuration.
    """
    logger.info(f"Starting Nuclei phase for scan {scan.id}")

    # Get ALL open ports (not just HTTP)
    all_ports = db.query(Port).join(ScanTarget).filter(
        ScanTarget.scan_id == str(scan.id),
        Port.state == 'open'
    ).all()

    if not all_ports:
        logger.info("No open ports for Nuclei scanning")
        set_phase_progress(db, scan, 'nuclei')
        return

    # Get excluded templates once for all scans
    excluded_templates = get_excluded_templates()

    # Filter ports that have scannable profiles
    scan_mode = getattr(config, 'scan_mode', 'deep') or 'deep'
    scannable_ports = []
    for port_rec in all_ports:
        # Query httpx result for technology detection and TLS info
        httpx_result = db.query(HttpxResult).filter(
            HttpxResult.port_id == str(port_rec.id)
        ).first()
        technologies = httpx_result.technologies if httpx_result and httpx_result.technologies else []

        profile = get_nuclei_profile(
            service_name=port_rec.service_name,
            product=port_rec.product,
            version=port_rec.version,
            port=port_rec.port,
            scan_mode=scan_mode,
            technologies=technologies
        )
        if profile.should_scan:
            if technologies:
                logger.info(f"Nuclei: port {port_rec.port} enhanced with technologies {technologies} -> tags {profile.tags}")
            # Store httpx_result for TLS-aware URL building
            scannable_ports.append((port_rec, profile, httpx_result))

    if not scannable_ports:
        logger.info("No scannable services found for Nuclei")
        set_phase_progress(db, scan, 'nuclei')
        return

    total = len(scannable_ports)
    begin_phase_steps(db, scan, 'nuclei', total)
    scanned = 0
    skipped = 0
    failed = 0
    vulns_found = 0

    logger.info(f"Nuclei: {total} scannable ports from {len(all_ports)} total open ports")

    for port_rec, profile, httpx_result in scannable_ports:
        target = db.query(ScanTarget).filter(
            ScanTarget.id == port_rec.scan_target_id
        ).first()

        if not target:
            skipped += 1
            set_phase_progress(db, scan, 'nuclei', scanned + skipped, total)
            continue

        ip = target.ip_address
        port = port_rec.port

        # Validate tags have templates (skip if no templates found)
        if profile.tags:
            has_templates, template_count = validate_tags(profile.tags)
            if not has_templates:
                logger.warning(f"No templates found for tags {profile.tags} on {ip}:{port}, skipping")
                skipped += 1
                set_phase_progress(db, scan, 'nuclei', scanned + skipped, total)
                continue
            logger.debug(f"Tags {profile.tags} have {template_count} templates")

        # Build target string based on profile and httpx TLS detection
        nuclei_target = build_nuclei_target(
            ip, port, profile,
            httpx_result=httpx_result,
            service_name=port_rec.service_name
        )
        tags_info = f"tags={profile.tags}" if profile.tags else "tags=[] (comprehensive)"
        logger.info(f"Nuclei: {nuclei_target} {tags_info} service={port_rec.service_name}")

        # Create tool execution record, linked directly to the Port. The
        # placeholder command line is replaced by the exact one after the run.
        tool_exec = start_tool_exec(db, target, "nuclei", port_rec,
                                    command_line=f"nuclei -target {nuclei_target}")

        try:
            # Calculate timeout with profile multiplier
            base_timeout = config.nuclei_timeout or 300
            if config.global_tool_timeout_seconds:
                base_timeout = config.global_tool_timeout_seconds
            timeout = int(base_timeout * profile.timeout_multiplier)

            # Use profile-specific rate limit or default
            rate_limit = profile.rate_limit or 150

            result = run_nuclei(
                target=nuclei_target,
                severity=config.nuclei_severity or "critical,high,medium,low,info",
                templates=config.nuclei_templates,
                tags=profile.tags if profile.tags else None,  # None = comprehensive (no tag filter)
                timeout=timeout,
                rate_limit=rate_limit,
                exclude_templates=excluded_templates
            )
            success, raw_jsonl, error = result

            # Save debug output (only when DEBUG=True)
            save_nuclei_debug(
                target=ip,
                raw_jsonl=raw_jsonl,
                scan_id=str(scan.id),
                port=port
            )

            # Update tool execution.
            # IMPORTANT: full raw_output is set BEFORE parsing and truncated AFTER:
            # the parser reads from tool_exec.raw_output, so it needs full data first
            record_tool_result(tool_exec, result, raw_output=raw_jsonl, raw_format="jsonl")

            if success:
                # Parse and create Vulnerability records (pass port_rec for direct linking)
                vulns = create_vulnerabilities_from_nuclei(
                    db, tool_exec, target, port_rec,
                    discovery_source='port'  # Explicit: per-port nuclei scanning
                )
                vulns_found += len(vulns)

                # Log observability info
                logger.info(f"Nuclei output: {len(raw_jsonl) if raw_jsonl else 0} bytes, parsed {len(vulns)} vulnerabilities for {nuclei_target}")

                # Update scan vulnerability count
                scan.total_vulnerabilities += len(vulns)
            else:
                logger.warning(f"Nuclei failed for {nuclei_target}: {error}")
                failed += 1
                if raw_jsonl and raw_jsonl.strip():
                    # Timed out (or died) after reporting findings: keep them.
                    # The run still counts as failed on its ToolExecution.
                    vulns = create_vulnerabilities_from_nuclei(
                        db, tool_exec, target, port_rec, discovery_source='port'
                    )
                    vulns_found += len(vulns)
                    scan.total_vulnerabilities += len(vulns)
                    logger.info(f"Nuclei: kept {len(vulns)} partial finding(s) for {nuclei_target}")

            # Now truncate for storage (parsing already complete on full data)
            tool_exec.raw_output = _truncate(raw_jsonl)

            db.commit()
            scanned += 1

        except Exception as e:
            logger.error(f"Nuclei error for {nuclei_target}: {e}")
            fail_tool_exec(db, tool_exec, e)
            skipped += 1
            failed += 1

        set_phase_progress(db, scan, 'nuclei', scanned + skipped, total)

    logger.info(
        f"Nuclei complete: {scanned} scanned ({failed} failed), {skipped} skipped, "
        f"{vulns_found} vulnerabilities found"
    )


def _endpoint_scan_host(url) -> Optional[str]:
    """Host of a discovered endpoint if it is safe to hand to nuclei, else None."""
    if not isinstance(url, str) or not url or len(url) > 2048:
        return None
    # No whitespace/control characters: the URL is written to a line-based list file
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7f for ch in url):
        return None
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
    except ValueError:
        return None
    if parsed.scheme not in ('http', 'https') or not host:
        return None
    return host


def run_nuclei_endpoints_phase(db, scan: Scan, targets: List[ScanTarget], config):
    """
    Run Nuclei against discovered endpoints (URLs from Katana).

    This phase scans the endpoints discovered by Katana using HTTP-relevant
    Nuclei templates. It's designed to find vulnerabilities in web paths
    that wouldn't be covered by per-port scanning.

    Safety limits:
    - Max 500 endpoints per host
    - Rate limited to 50 rps by default
    - HTTP-relevant tags only (http, cve, exposure, misconfig, tech)
    """
    logger.info(f"Starting Nuclei endpoints phase for scan {scan.id}")

    # Get all discovered endpoints for this scan
    endpoints = db.query(DiscoveredEndpoint).filter(
        DiscoveredEndpoint.scan_id == str(scan.id)
    ).all()

    if not endpoints:
        logger.info("No discovered endpoints for Nuclei endpoint scanning")
        set_phase_progress(db, scan, 'nuclei_endpoints')
        return

    # Get excluded templates
    excluded_templates = get_excluded_templates()

    # Group endpoints by host (target). URLs come from crawler output, i.e.
    # from the scanned site: only http(s) URLs whose host is exactly a scan
    # target are scanned, so a crafted link cannot add off-target hosts.
    targets_by_ip = {t.ip_address: t for t in targets}
    endpoints_by_target = {}
    rejected = 0
    for endpoint in endpoints:
        target = targets_by_ip.get(_endpoint_scan_host(endpoint.url))
        if target is None:
            rejected += 1
            continue

        if target.id not in endpoints_by_target:
            endpoints_by_target[target.id] = {'target': target, 'urls': []}
        # Cap at 500 endpoints per host for safety
        if len(endpoints_by_target[target.id]['urls']) < 500:
            endpoints_by_target[target.id]['urls'].append(endpoint.url)

    if rejected:
        logger.warning(f"Nuclei endpoints: skipped {rejected} endpoint(s) that are not plain http(s) URLs on a scan target")

    total_targets = len(endpoints_by_target)
    if total_targets == 0:
        logger.info("No endpoints matched to scan targets")
        set_phase_progress(db, scan, 'nuclei_endpoints')
        return

    begin_phase_steps(db, scan, 'nuclei_endpoints', total_targets)
    scanned = 0
    vulns_found = 0

    logger.info(f"Nuclei endpoints: {len(endpoints)} total endpoints across {total_targets} targets")

    for target_id, data in endpoints_by_target.items():
        target = data['target']
        urls = data['urls']

        logger.info(f"Nuclei endpoints: scanning {len(urls)} URLs for {target.ip_address}")

        # Write URLs to a private temp file (removed in the finally below)
        fd, urls_file = tempfile.mkstemp(prefix='nuclei_urls_', suffix='.txt')
        with os.fdopen(fd, 'w') as f:
            for url in urls:
                f.write(url + '\n')

        tool_exec = None
        try:
            # Create tool execution record
            tool_exec = start_tool_exec(
                db, target, "nuclei-endpoints",
                command_line=f"nuclei -list <{len(urls)} urls> -tags http,cve,exposure,misconfig,tech",
            )

            # Get timeout from config
            timeout = getattr(config, 'nuclei_endpoint_timeout', 600) or 600
            if config.global_tool_timeout_seconds:
                timeout = config.global_tool_timeout_seconds

            # Get severity from config
            severity_list = getattr(config, 'nuclei_endpoint_severity', ['critical', 'high', 'medium']) or ['critical', 'high', 'medium']
            severity = ','.join(severity_list) if isinstance(severity_list, list) else severity_list

            result = run_nuclei_list(
                urls_file=urls_file,
                severity=severity,
                tags=['http', 'cve', 'exposure', 'misconfig', 'tech'],
                timeout=timeout,
                rate_limit=50,  # Conservative rate limit for safety
                exclude_templates=excluded_templates
            )
            success, raw_jsonl, error = result

            # Full raw output first (the parser reads it), truncated below
            record_tool_result(tool_exec, result, raw_output=raw_jsonl, raw_format="jsonl")

            if success:
                # Parse and create Vulnerability records with discovery_source='endpoint'
                vulns = create_vulnerabilities_from_nuclei(
                    db, tool_exec, target,
                    port_rec=None,
                    discovery_source='endpoint'
                )
                vulns_found += len(vulns)

                logger.info(f"Nuclei endpoints: {len(raw_jsonl) if raw_jsonl else 0} bytes output, {len(vulns)} vulnerabilities for {target.ip_address}")

                # Update scan vulnerability count
                scan.total_vulnerabilities += len(vulns)
            else:
                logger.warning(f"Nuclei endpoints failed for {target.ip_address}: {error}")
                if raw_jsonl and raw_jsonl.strip():
                    # Partial findings of a run that timed out: keep them
                    vulns = create_vulnerabilities_from_nuclei(
                        db, tool_exec, target, port_rec=None, discovery_source='endpoint'
                    )
                    vulns_found += len(vulns)
                    scan.total_vulnerabilities += len(vulns)

            # Truncate for storage
            tool_exec.raw_output = _truncate(raw_jsonl)

            db.commit()

        except Exception as e:
            logger.error(f"Nuclei endpoints error for {target.ip_address}: {e}")
            fail_tool_exec(db, tool_exec, e)

        finally:
            # Cleanup temp file
            try:
                os.unlink(urls_file)
            except OSError:
                pass

        # Count the target whether it succeeded or not so progress always advances
        scanned += 1
        set_phase_progress(db, scan, 'nuclei_endpoints', scanned, total_targets)

    logger.info(f"Nuclei endpoints complete: {scanned} targets scanned, {vulns_found} vulnerabilities found")


def run_nse_phase(db, scan: Scan, targets: List[ScanTarget], config):
    """
    Run NSE (Nmap Scripting Engine) scripts on discovered services.

    NSE scripts provide detailed security analysis for specific services
    like RDP encryption level, NTP monlist vulnerability, etc.
    """
    logger.info(f"Starting NSE phase for scan {scan.id}")

    nse_service = get_nse_profile_service()
    if not nse_service.is_enabled():
        logger.info("NSE scanning is disabled in configuration")
        return

    # Get all open ports with their service info
    all_ports = db.query(Port).join(ScanTarget).filter(
        ScanTarget.scan_id == str(scan.id),
        Port.state == 'open'
    ).all()

    if not all_ports:
        logger.info("No open ports for NSE scanning")
        return

    # Build list of ports with their services for profile matching
    ports_info = []
    for port in all_ports:
        ports_info.append({
            'port': port.port,
            'protocol': port.protocol,
            'service_name': port.service_name,
            'port_record': port
        })

    # Get ports that have matching NSE profiles
    ports_with_nse = nse_service.get_ports_for_nse(ports_info)

    if not ports_with_nse:
        logger.info("No services matched NSE profiles")
        return

    logger.info(f"NSE: {len(ports_with_nse)} ports matched profiles from {len(all_ports)} total")

    total = len(ports_with_nse)
    begin_phase_steps(db, scan, 'nse', total)
    completed = 0
    findings_total = 0

    for port_info in ports_with_nse:
        port_record = port_info['port_record']
        scripts = port_info['scripts']
        profile_name = port_info['profile']
        timeout = port_info.get('timeout', 300)

        # Get target for this port
        target = db.query(ScanTarget).filter(
            ScanTarget.id == port_record.scan_target_id
        ).first()

        if not target:
            completed += 1
            continue

        ip = target.ip_address
        port = port_record.port
        protocol = port_record.protocol

        logger.info(f"NSE: Running {len(scripts)} scripts on {ip}:{port} (profile: {profile_name})")

        # Create tool execution record (exact command line comes from the runner)
        tool_exec = start_tool_exec(
            db, target, "nmap-nse", port_record,
            command_line=f"nmap -p{port} --script={','.join(scripts)} {ip}",
        )

        try:
            # Run NSE scripts
            result = run_nmap_nse(
                ip=ip,
                port=port,
                scripts=scripts,
                protocol=protocol,
                timeout=timeout
            )
            success, raw_xml, error = result

            record_tool_result(tool_exec, result, raw_output=_truncate(raw_xml), raw_format="xml")
            if not success:
                logger.warning(f"NSE failed for {ip}:{port}: {error}")

            if success and raw_xml:
                # Parse NSE output
                try:
                    findings = parse_nse_output(raw_xml)
                    for finding in findings:
                        severity = determine_nse_severity(
                            finding['script_id'],
                            finding['output'],
                            finding['elements']
                        )

                        nse_finding = NseFinding(
                            id=str(uuid.uuid4()),
                            port_id=str(port_record.id),
                            tool_execution_id=str(tool_exec.id),
                            script_id=finding['script_id'],
                            profile_name=profile_name,
                            raw_output=finding['output'],
                            elements=finding['elements'],
                            severity=severity
                        )
                        db.add(nse_finding)
                        findings_total += 1

                except Exception as parse_error:
                    logger.error(f"NSE parse error for {ip}:{port}: {parse_error}")
                    tool_exec.error_message = f"Parse error: {parse_error}"

            db.commit()

        except Exception as e:
            logger.error(f"NSE error for {ip}:{port}: {e}")
            fail_tool_exec(db, tool_exec, e)

        completed += 1

        set_phase_progress(db, scan, 'nse', completed, total)

    logger.info(f"NSE complete: {completed} ports scanned, {findings_total} findings")


def run_sslscan_phase(db, scan: Scan, targets: List[ScanTarget], config):
    """
    Run sslscan on discovered SSL/TLS services.

    Analyzes TLS configuration, cipher suites, certificate details,
    and known vulnerabilities like Heartbleed.
    """
    logger.info(f"Starting sslscan phase for scan {scan.id}")

    # Ports that typically use SSL/TLS
    ssl_ports = [443, 8443, 993, 995, 465, 636, 990, 989, 4443, 9443]
    ssl_services = ['https', 'ssl/http', 'imaps', 'pop3s', 'smtps', 'ldaps', 'ftps']

    # Get ports that might have SSL/TLS
    ssl_port_records = db.query(Port).join(ScanTarget).filter(
        ScanTarget.scan_id == str(scan.id),
        Port.state == 'open'
    ).filter(
        # Port number match OR service name match
        (Port.port.in_(ssl_ports)) |
        (Port.service_name.in_(ssl_services))
    ).all()

    if not ssl_port_records:
        logger.info("No SSL/TLS ports found for sslscan")
        return

    logger.info(f"sslscan: {len(ssl_port_records)} potential SSL/TLS ports")

    total = len(ssl_port_records)
    begin_phase_steps(db, scan, 'sslscan', total)
    completed = 0
    results_total = 0

    for port_record in ssl_port_records:
        # Get target for this port
        target = db.query(ScanTarget).filter(
            ScanTarget.id == port_record.scan_target_id
        ).first()

        if not target:
            completed += 1
            continue

        ip = target.ip_address
        port = port_record.port

        logger.info(f"sslscan: Scanning {ip}:{port}")

        # Create tool execution record (exact command line comes from the runner)
        tool_exec = start_tool_exec(db, target, "sslscan", port_record,
                                    command_line=f"sslscan {ip}:{port}")

        try:
            # Run sslscan
            sslscan_timeout = config.global_tool_timeout_seconds or 60
            result = run_sslscan(
                ip=ip,
                port=port,
                timeout=sslscan_timeout,
                connect_timeout=10
            )
            success, raw_xml, error = result

            record_tool_result(tool_exec, result, raw_output=_truncate(raw_xml), raw_format="xml")

            if success and raw_xml:
                try:
                    # Parse sslscan output
                    parsed = parse_sslscan_output(raw_xml)

                    if not parsed.get('connection_failed'):
                        # Analyze security and generate findings
                        findings = analyze_ssl_security(parsed)
                        grade = calculate_ssl_grade(findings)

                        # Create SslScanResult record
                        ssl_result = SslScanResult(
                            id=str(uuid.uuid4()),
                            port_id=str(port_record.id),
                            tool_execution_id=str(tool_exec.id),
                            sslv2_enabled=parsed.get('sslv2_enabled', False),
                            sslv3_enabled=parsed.get('sslv3_enabled', False),
                            tlsv10_enabled=parsed.get('tlsv10_enabled', False),
                            tlsv11_enabled=parsed.get('tlsv11_enabled', False),
                            tlsv12_enabled=parsed.get('tlsv12_enabled', False),
                            tlsv13_enabled=parsed.get('tlsv13_enabled', False),
                            fallback_scsv_supported=parsed.get('fallback_scsv_supported'),
                            secure_renegotiation=parsed.get('secure_renegotiation'),
                            compression_supported=parsed.get('compression_supported'),
                            heartbleed_vulnerable=parsed.get('heartbleed_vulnerable', False),
                            ciphers=parsed.get('ciphers'),
                            key_exchange_groups=parsed.get('key_exchange_groups'),
                            cert_subject=parsed.get('cert_subject'),
                            cert_issuer=parsed.get('cert_issuer'),
                            cert_altnames=parsed.get('cert_altnames'),
                            cert_not_before=parsed.get('cert_not_before'),
                            cert_not_after=parsed.get('cert_not_after'),
                            cert_expired=parsed.get('cert_expired'),
                            cert_self_signed=parsed.get('cert_self_signed'),
                            cert_signature_algorithm=parsed.get('cert_signature_algorithm'),
                            cert_key_type=parsed.get('cert_key_type'),
                            cert_key_bits=parsed.get('cert_key_bits'),
                            findings=findings,
                            grade=grade,
                            connection_failed=False
                        )
                        db.add(ssl_result)
                        results_total += 1
                    else:
                        # Connection failed
                        ssl_result = SslScanResult(
                            id=str(uuid.uuid4()),
                            port_id=str(port_record.id),
                            tool_execution_id=str(tool_exec.id),
                            connection_failed=True,
                            failure_reason=parsed.get('failure_reason', 'Unknown error')
                        )
                        db.add(ssl_result)

                except Exception as parse_error:
                    logger.error(f"sslscan parse error for {ip}:{port}: {parse_error}")
                    tool_exec.error_message = f"Parse error: {parse_error}"
            else:
                # Tool failed - record connection failure
                ssl_result = SslScanResult(
                    id=str(uuid.uuid4()),
                    port_id=str(port_record.id),
                    tool_execution_id=str(tool_exec.id),
                    connection_failed=True,
                    failure_reason=error or 'sslscan execution failed'
                )
                db.add(ssl_result)

            db.commit()

        except Exception as e:
            logger.error(f"sslscan error for {ip}:{port}: {e}")
            fail_tool_exec(db, tool_exec, e)

        completed += 1

        set_phase_progress(db, scan, 'sslscan', completed, total)

    logger.info(f"sslscan complete: {completed} ports scanned, {results_total} successful results")


def run_testssl_phase(db, scan: Scan, targets: List[ScanTarget], config):
    """
    Run testssl.sh for deep TLS/SSL analysis on TLS-capable ports.

    testssl.sh provides more comprehensive TLS analysis than sslscan including:
    - Protocol versions and cipher suites
    - Certificate chain validation
    - Known vulnerabilities (Heartbleed, POODLE, BEAST, DROWN, ROBOT, etc.)
    - Forward secrecy evaluation
    - HSTS, certificate transparency, OCSP stapling

    Uses get_tls_candidate_ports() from port_classifier for port selection.
    """
    logger.info(f"Starting testssl phase for scan {scan.id}")

    # Get TLS candidate ports using port_classifier
    tls_ports = get_tls_candidate_ports(db, scan.id)

    if not tls_ports:
        logger.info("No TLS ports found for testssl analysis")
        return

    logger.info(f"testssl: {len(tls_ports)} potential TLS ports")

    # Get timeout from config (default 300s)
    timeout = getattr(config, 'testssl_timeout', 300) or 300

    total = len(tls_ports)
    begin_phase_steps(db, scan, 'testssl', total)
    completed = 0
    results_total = 0

    for port_record in tls_ports:
        # Get target for this port
        target = db.query(ScanTarget).filter(
            ScanTarget.id == port_record.scan_target_id
        ).first()

        if not target:
            completed += 1
            continue

        host = target.ip_address
        port = port_record.port

        logger.info(f"testssl: Scanning {host}:{port}")

        # Create tool execution record (exact command line comes from the runner)
        tool_exec = start_tool_exec(db, target, "testssl", port_record,
                                    command_line=f"testssl {host}:{port}")

        try:
            # Run testssl.sh
            output = run_testssl(
                host=host,
                port=port,
                timeout=timeout,
                fast_mode=True
            )

            # Raw output (also partial output of a failed/timed-out run) is kept
            record_tool_result(tool_exec, output, raw_output=_truncate(output.raw_json), raw_format='json')

            if output.success and output.parsed_data:
                try:
                    # Parse testssl output
                    parsed = parse_testssl_output(output.parsed_data)

                    # Save raw JSON to artifact storage
                    artifact_path = None
                    if output.raw_json:
                        artifact_path = artifact_storage.save_artifact(
                            scan_id=str(scan.id),
                            tool_execution_id=str(tool_exec.id),
                            content=output.raw_json,
                            extension='json'
                        )
                        tool_exec.artifact_path = artifact_path
                        tool_exec.raw_format = 'json'

                    if not parsed.get('connection_failed'):
                        # Create TestsslResult record
                        testssl_result = TestsslResult(
                            id=str(uuid.uuid4()),
                            scan_id=str(scan.id),
                            scan_target_id=str(target.id),
                            port_id=str(port_record.id),
                            tool_execution_id=str(tool_exec.id),
                            host=host,
                            port=port,
                            connection_failed=False,
                            protocols=parsed.get('protocols'),
                            certificate_info=parsed.get('certificate_info'),
                            vulnerabilities=parsed.get('vulnerabilities'),
                            cipher_findings=parsed.get('cipher_findings'),
                            server_config=parsed.get('server_config'),
                            overall_grade=parsed.get('overall_grade'),
                            artifact_path=artifact_path,
                        )
                        db.add(testssl_result)
                        results_total += 1
                        logger.info(f"testssl: {host}:{port} - grade {parsed.get('overall_grade', 'N/A')}")
                    else:
                        # Connection failed
                        testssl_result = TestsslResult(
                            id=str(uuid.uuid4()),
                            scan_id=str(scan.id),
                            scan_target_id=str(target.id),
                            port_id=str(port_record.id),
                            tool_execution_id=str(tool_exec.id),
                            host=host,
                            port=port,
                            connection_failed=True,
                            failure_reason=parsed.get('failure_reason', 'Unknown error'),
                            artifact_path=artifact_path,
                        )
                        db.add(testssl_result)
                        logger.warning(f"testssl: {host}:{port} connection failed - {parsed.get('failure_reason')}")

                except Exception as parse_error:
                    logger.error(f"testssl parse error for {host}:{port}: {parse_error}")
                    tool_exec.error_message = f"Parse error: {parse_error}"
            else:
                # Tool execution failed
                testssl_result = TestsslResult(
                    id=str(uuid.uuid4()),
                    scan_id=str(scan.id),
                    scan_target_id=str(target.id),
                    port_id=str(port_record.id),
                    tool_execution_id=str(tool_exec.id),
                    host=host,
                    port=port,
                    connection_failed=True,
                    failure_reason=output.error or 'testssl execution failed',
                )
                db.add(testssl_result)
                logger.warning(f"testssl: {host}:{port} failed - {output.error}")

            db.commit()

        except Exception as e:
            logger.error(f"testssl error for {host}:{port}: {e}")
            fail_tool_exec(db, tool_exec, e)

        completed += 1

        set_phase_progress(db, scan, 'testssl', completed, total)

    logger.info(f"testssl complete: {completed} ports scanned, {results_total} successful results")


def run_nikto_phase(db, scan: Scan, targets: List[ScanTarget], config):
    """
    Run Nikto web server scanner against HTTP/HTTPS ports.

    Nikto is a comprehensive web server scanner that checks for:
    - Server misconfigurations
    - Outdated software versions
    - Dangerous files/CGIs
    - Server-specific problems
    """
    logger.info(f"Starting Nikto phase for scan {scan.id}")
    begin_phase_steps(db, scan, 'nikto')

    # HTTP services to scan
    http_services = ['http', 'https', 'ssl/http', 'http-proxy', 'http-alt']

    total_scanned = 0
    total_findings = 0

    for target in targets:
        # Find HTTP/HTTPS ports for this target
        http_ports = db.query(Port).filter(
            Port.scan_target_id == str(target.id),
            Port.state == 'open',
            Port.service_name.in_(http_services)
        ).all()

        if not http_ports:
            logger.debug(f"No HTTP ports found for {target.ip_address}, skipping Nikto")
            continue

        logger.info(f"Nikto: Found {len(http_ports)} HTTP port(s) for {target.ip_address}")

        for port_rec in http_ports:
            ip = target.ip_address
            port = port_rec.port

            # Get httpx result if available (for TLS detection)
            httpx_result = port_rec.httpx_results[0] if port_rec.httpx_results else None

            # Use shared protocol detection utility
            protocol = determine_http_protocol(
                ip=ip,
                port=port,
                service_name=port_rec.service_name,
                httpx_result=httpx_result,
                profile_protocol='http'
            )
            ssl = (protocol == 'https')

            logger.info(f"Nikto: Scanning {ip}:{port} (ssl={ssl})")

            # Create tool execution record (exact command line comes from the runner)
            cmd_line = f"nikto -h {ip} -p {port} -Format json"
            if ssl:
                cmd_line += " -ssl"

            tool_exec = start_tool_exec(db, target, "nikto", port_rec, command_line=cmd_line)

            try:
                # Run Nikto
                timeout = config.nikto_timeout or 120
                result = run_nikto(
                    target=ip,
                    port=port,
                    timeout=timeout,
                    ssl=ssl
                )
                success, raw_json, error = result

                # Full output first (the parser reads it), truncated below
                record_tool_result(tool_exec, result, raw_output=raw_json, raw_format="json")

                if success and raw_json:
                    # Parse and create vulnerability records
                    vulns = create_vulnerabilities_from_nikto(
                        db=db,
                        tool_execution=tool_exec,
                        target=target,
                        port_rec=port_rec,
                        host=ip,
                        port=port
                    )
                    total_findings += len(vulns)
                    logger.info(f"Nikto found {len(vulns)} findings for {ip}:{port}")
                else:
                    logger.warning(f"Nikto scan failed for {ip}:{port}: {error}")

                tool_exec.raw_output = _truncate(raw_json)

                db.commit()
                total_scanned += 1

            except Exception as e:
                logger.error(f"Nikto error for {ip}:{port}: {e}")
                fail_tool_exec(db, tool_exec, e)

    # Update scan statistics
    from ..models.vulnerability import Vulnerability
    total_vulns = db.query(Vulnerability).join(ScanTarget).filter(
        ScanTarget.scan_id == str(scan.id)
    ).count()
    scan.total_vulnerabilities = total_vulns
    db.commit()
    set_phase_progress(db, scan, 'nikto')

    logger.info(f"Nikto complete: {total_scanned} ports scanned, {total_findings} findings")


def run_zap_phase(db, scan: Scan, targets: List[ScanTarget], config):
    """
    Run OWASP ZAP baseline scan against HTTP/HTTPS ports.

    ZAP provides:
    - Spider crawling to discover pages
    - Passive scanning for security issues
    - Active scanning (optional) for deeper analysis
    """
    logger.info(f"Starting ZAP phase for scan {scan.id}")
    begin_phase_steps(db, scan, 'zap')

    # Check if ZAP is available
    if not check_zap_available():
        logger.warning("ZAP container not available, skipping ZAP phase")
        return

    # HTTP services to scan
    http_services = ['http', 'https', 'ssl/http', 'http-proxy', 'http-alt']

    total_scanned = 0
    total_findings = 0

    for target in targets:
        # Find HTTP/HTTPS ports for this target
        http_ports = db.query(Port).filter(
            Port.scan_target_id == str(target.id),
            Port.state == 'open',
            Port.service_name.in_(http_services)
        ).all()

        if not http_ports:
            logger.debug(f"No HTTP ports found for {target.ip_address}, skipping ZAP")
            continue

        logger.info(f"ZAP: Found {len(http_ports)} HTTP port(s) for {target.ip_address}")

        for port_rec in http_ports:
            ip = target.ip_address
            port = port_rec.port

            # Get httpx result if available (for TLS detection)
            httpx_result = port_rec.httpx_results[0] if port_rec.httpx_results else None

            # Use shared protocol detection utility
            scheme = determine_http_protocol(
                ip=ip,
                port=port,
                service_name=port_rec.service_name,
                httpx_result=httpx_result,
                profile_protocol='http'
            )
            target_url = f"{scheme}://{ip}:{port}"

            logger.info(f"ZAP: Scanning {target_url}")

            # Create tool execution record (ZAP is driven over its API, so the
            # runner reports the API calls it made as the "command line")
            tool_exec = start_tool_exec(db, target, "zap", port_rec,
                                        command_line=f"zap-baseline {target_url}")

            try:
                # Run ZAP baseline scan
                timeout = config.zap_timeout or 300
                result = run_zap_baseline(
                    target_url=target_url,
                    timeout=timeout,
                    spider_timeout=60
                )
                success, alerts_json, error = result

                # Full output first (the parser reads it), truncated below
                record_tool_result(tool_exec, result, raw_output=alerts_json, raw_format="json")

                if success and alerts_json:
                    # Parse and create vulnerability records
                    vulns = create_vulnerabilities_from_zap(
                        db=db,
                        tool_execution=tool_exec,
                        target=target,
                        port_rec=port_rec,
                        host=ip,
                        port=port
                    )
                    total_findings += len(vulns)
                    logger.info(f"ZAP found {len(vulns)} findings for {target_url}")
                else:
                    logger.warning(f"ZAP scan failed for {target_url}: {error}")

                tool_exec.raw_output = _truncate(alerts_json)

                db.commit()
                total_scanned += 1

            except Exception as e:
                logger.error(f"ZAP error for {target_url}: {e}")
                fail_tool_exec(db, tool_exec, e)

    # Update scan statistics
    from ..models.vulnerability import Vulnerability
    total_vulns = db.query(Vulnerability).join(ScanTarget).filter(
        ScanTarget.scan_id == str(scan.id)
    ).count()
    scan.total_vulnerabilities = total_vulns
    db.commit()
    set_phase_progress(db, scan, 'zap')

    logger.info(f"ZAP complete: {total_scanned} ports scanned, {total_findings} findings")
