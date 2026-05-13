from celery import Task
from datetime import datetime
from typing import List, Tuple, Optional, Any, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..celery_app import celery_app
from ..db.sync_session import get_sync_db, SessionLocal
from ..models import Scan, ScanTarget, ToolExecution, ScanStatus, ScanPhase, TargetStatus, Port
from ..tools.masscan import run_masscan
from ..tools.nmap import run_nmap, run_nmap_discovery
from ..tools.ssh_audit import run_ssh_audit
from ..tools.nuclei import run_nuclei, run_nuclei_list
from ..parsers.masscan_parser import create_ports_from_masscan
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
from sqlalchemy import select
import uuid
import logging
import shutil
import tempfile

logger = logging.getLogger(__name__)
import threading

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

    Phase 1: Port Discovery (0% -> 10%)
    Phase 2: Nmap Service Detection (10% -> 75%)
    Phase 3: httpx HTTP Probing (75% -> 78%)
    Phase 3.5: Katana Endpoint Discovery (78% -> 80%)
    Phase 4: SSH-Audit (80% -> 85%)
    Phase 5: Nuclei (85% -> 92%)
    Phase 6: NSE Scripts (92% -> 95%)
    Phase 7: SSLScan (95% -> 96%)
    Phase 7.5: testssl.sh Deep TLS Analysis (96% -> 97%)
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

        # Update scan status
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = datetime.utcnow()
        scan.current_phase = ScanPhase.NMAP_DISCOVERY.value
        db.commit()

        try:
            # Load targets
            targets = db.query(ScanTarget).filter(
                ScanTarget.scan_id == scan_id
            ).order_by(ScanTarget.sequence).all()

            # Phase 1: Port Discovery (0% -> 10%)
            self.update_state(state='PROGRESS', meta={'phase': 'nmap_discovery', 'progress': 0})
            run_masscan_phase(db, scan, targets, config)

            # Update total_open_ports after discovery phase completes
            total_ports = db.query(Port).join(ScanTarget).filter(
                ScanTarget.scan_id == scan_id
            ).count()
            scan.total_open_ports = total_ports
            db.commit()

            # Phase 2: Nmap (10% -> 75%)
            scan.current_phase = ScanPhase.NMAP.value
            db.commit()
            self.update_state(state='PROGRESS', meta={'phase': 'nmap', 'progress': 0.1})
            run_nmap_phase(db, scan, targets, config)

            # Phase 3: httpx HTTP probing (75% -> 78%)
            if getattr(config, 'enable_httpx', True):
                scan.current_phase = ScanPhase.HTTPX.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'httpx', 'progress': 0.75})
                run_httpx_phase(db, scan, targets, config)

            # Phase 3.5: Katana endpoint discovery (78% -> 80%)
            if getattr(config, 'enable_katana', False):
                scan.current_phase = ScanPhase.KATANA.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'katana', 'progress': 0.78})
                run_katana_phase(db, scan, targets, config)

            # Phase 4: SSH-Audit (80% -> 85%)
            if config.enable_ssh_audit:
                scan.current_phase = ScanPhase.SSH_AUDIT.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'ssh-audit', 'progress': 0.8})
                run_ssh_audit_phase(db, scan, targets, config)

            # Phase 5: Nuclei per-port (85% -> 88%)
            if config.enable_nuclei:
                scan.current_phase = ScanPhase.NUCLEI.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'nuclei', 'progress': 0.85})
                run_nuclei_phase(db, scan, targets, config)

            # Phase 5.5: Nuclei endpoint-mode (88% -> 91%)
            # Scans discovered endpoints from Katana
            if getattr(config, 'enable_nuclei_endpoints', False):
                scan.current_phase = ScanPhase.NUCLEI_ENDPOINTS.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'nuclei_endpoints', 'progress': 0.88})
                run_nuclei_endpoints_phase(db, scan, targets, config)

            # Phase 6: NSE Scripts (91% -> 93%)
            # NSE runs after nmap service detection to get detailed service info
            self.update_state(state='PROGRESS', meta={'phase': 'nse', 'progress': 0.91})
            run_nse_phase(db, scan, targets, config)

            # Phase 7: sslscan (93% -> 95%)
            # sslscan runs on SSL/TLS ports for TLS posture analysis
            if getattr(config, 'enable_sslscan', True):
                scan.current_phase = ScanPhase.SSLSCAN.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'sslscan', 'progress': 0.93})
                run_sslscan_phase(db, scan, targets, config)

            # Phase 7.5: testssl.sh (95% -> 97%)
            # Deep TLS analysis with testssl.sh (more comprehensive than sslscan)
            if getattr(config, 'enable_testssl', False):
                scan.current_phase = ScanPhase.TESTSSL.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'testssl', 'progress': 0.95})
                run_testssl_phase(db, scan, targets, config)

            # Phase 8: Nikto (97% -> 98%)
            if config.enable_nikto:
                scan.current_phase = ScanPhase.NIKTO.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'nikto', 'progress': 0.97})
                run_nikto_phase(db, scan, targets, config)

            # Phase 9: ZAP (98% -> 100%)
            if config.enable_zap:
                scan.current_phase = ScanPhase.ZAP.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'zap', 'progress': 0.98})
                run_zap_phase(db, scan, targets, config)

            # Mark scan as completed
            scan.status = ScanStatus.COMPLETED.value
            scan.current_phase = ScanPhase.COMPLETED.value
            scan.finished_at = datetime.utcnow()
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

        except Exception as e:
            scan.status = ScanStatus.FAILED.value
            scan.current_phase = ScanPhase.FAILED.value
            scan.finished_at = datetime.utcnow()
            db.commit()
            raise

def run_masscan_phase(db, scan: Scan, targets: List[ScanTarget], config):
    """
    Run port discovery on all targets sequentially.

    Note: We use nmap for port discovery instead of masscan because masscan
    has reliability issues in Docker environments (SYN packets don't receive
    responses reliably with bridge networking).

    For SQLite backends, we process targets sequentially.
    """
    total = len(targets)
    completed = 0

    for target in targets:
        try:
            # Run nmap discovery for this target (uses same db session)
            scan_target_with_nmap_discovery(db, target, config)
        except Exception as e:
            # Log error but continue
            target.status = TargetStatus.FAILED.value
            target.error_message = str(e)
            target.finished_at = datetime.utcnow()
            db.commit()

        completed += 1

        # Update progress (discovery is 10% of total)
        progress = (completed / total) * 0.1
        scan.progress_percent = progress
        scan.progress_updated_at = datetime.utcnow()
        db.commit()

def scan_target_with_nmap_discovery(db, target: ScanTarget, config):
    """Execute nmap discovery for a single target using the provided db session."""
    target.status = TargetStatus.SCANNING.value
    target.started_at = datetime.utcnow()
    db.commit()

    # Use discovery timeout (shorter than full nmap service scan)
    timeout = int(config.host_timeout_seconds * config.masscan_timeout_percent)
    if config.global_tool_timeout_seconds:
        timeout = config.global_tool_timeout_seconds

    tool_exec = ToolExecution(
        id=str(uuid.uuid4()),
        scan_target_id=str(target.id),
        tool_name="nmap-discovery",
        started_at=datetime.utcnow()
    )
    db.add(tool_exec)
    db.commit()

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

    success, raw_xml, error = run_nmap_discovery(
        ip=target.ip_address,
        timing_template="T4",  # Fast timing
        timeout=discovery_timeout,
        top_ports=top_ports,
        additional_ports=additional_ports,
        full_scan=full_scan
    )

    # Save debug output (only when DEBUG=True)
    # Get scan_id from target's relationship
    scan_id = target.scan_id if hasattr(target, 'scan_id') else None
    save_nmap_debug(
        target=target.ip_address,
        raw_xml=raw_xml,
        scan_id=str(scan_id) if scan_id else None,
        phase="discovery"
    )

    tool_exec.finished_at = datetime.utcnow()
    tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
    tool_exec.raw_output = raw_xml
    tool_exec.raw_format = "xml"
    tool_exec.error_message = error
    tool_exec.exit_code = 0 if success else 1

    if success:
        create_ports_from_nmap_discovery(db, tool_exec, target)
        target.status = TargetStatus.COMPLETED.value
    else:
        target.status = TargetStatus.FAILED.value
        target.error_message = error

    target.finished_at = datetime.utcnow()
    target.duration_seconds = (target.finished_at - target.started_at).total_seconds()
    db.commit()


def scan_target_with_masscan_sequential(db, target: ScanTarget, config):
    """Execute masscan for a single target using the provided db session. DEPRECATED - use nmap discovery."""
    target.status = TargetStatus.SCANNING.value
    target.started_at = datetime.utcnow()
    db.commit()

    timeout = int(config.host_timeout_seconds * config.masscan_timeout_percent)
    if config.global_tool_timeout_seconds:
        timeout = config.global_tool_timeout_seconds

    tool_exec = ToolExecution(
        id=str(uuid.uuid4()),
        scan_target_id=str(target.id),
        tool_name="masscan",
        started_at=datetime.utcnow()
    )
    db.add(tool_exec)
    db.commit()

    success, raw_json, error = run_masscan(
        ip=target.ip_address,
        rate=config.masscan_rate,
        interface=config.masscan_interface,
        timeout=timeout
    )

    tool_exec.finished_at = datetime.utcnow()
    tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
    tool_exec.raw_output = raw_json
    tool_exec.raw_format = "json"
    tool_exec.error_message = error
    tool_exec.exit_code = 0 if success else 1

    if success:
        create_ports_from_masscan(db, tool_exec, target)
        target.status = TargetStatus.COMPLETED.value
    else:
        target.status = TargetStatus.FAILED.value
        target.error_message = error

    target.finished_at = datetime.utcnow()
    target.duration_seconds = (target.finished_at - target.started_at).total_seconds()
    db.commit()


def scan_target_with_masscan_thread_safe(target_id: str, config_id: str) -> Tuple[bool, Optional[str]]:
    """
    Execute masscan for a single target with its own database session.

    This function is designed to run in a thread pool, creating its own
    database session to avoid SQLAlchemy threading issues.

    Returns:
        Tuple of (success: bool, error_message: Optional[str])
    """
    db = SessionLocal()
    try:
        # Load target and config in this thread's session
        target = db.query(ScanTarget).filter(ScanTarget.id == target_id).first()
        if not target:
            return False, f"Target {target_id} not found"

        from ..models import ScanConfig
        config = db.query(ScanConfig).filter(ScanConfig.id == config_id).first()
        if not config:
            return False, f"Config {config_id} not found"

        # Update target status
        target.status = TargetStatus.SCANNING.value
        target.started_at = datetime.utcnow()
        db.commit()

        timeout = int(config.host_timeout_seconds * config.masscan_timeout_percent)
        if config.global_tool_timeout_seconds:
            timeout = config.global_tool_timeout_seconds

        tool_exec = ToolExecution(
            id=str(uuid.uuid4()),
            scan_target_id=str(target.id),
            tool_name="masscan",
            started_at=datetime.utcnow()
        )
        db.add(tool_exec)
        db.commit()

        success, raw_json, error = run_masscan(
            ip=target.ip_address,
            rate=config.masscan_rate,
            interface=config.masscan_interface,
            timeout=timeout
        )

        tool_exec.finished_at = datetime.utcnow()
        tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
        tool_exec.raw_output = raw_json
        tool_exec.raw_format = "json"
        tool_exec.error_message = error
        tool_exec.exit_code = 0 if success else 1

        if success:
            create_ports_from_masscan(db, tool_exec, target)
            target.status = TargetStatus.COMPLETED.value
        else:
            target.status = TargetStatus.FAILED.value
            target.error_message = error

        target.finished_at = datetime.utcnow()
        target.duration_seconds = (target.finished_at - target.started_at).total_seconds()
        db.commit()

        return True, None

    except Exception as e:
        db.rollback()
        return False, str(e)
    finally:
        db.close()


def scan_target_with_masscan(db, target: ScanTarget, config):
    """Execute masscan for a single target. DEPRECATED - use thread-safe version."""
    target.status = TargetStatus.SCANNING.value
    target.started_at = datetime.utcnow()
    db.commit()

    timeout = int(config.host_timeout_seconds * config.masscan_timeout_percent)
    if config.global_tool_timeout_seconds:
        timeout = config.global_tool_timeout_seconds

    tool_exec = ToolExecution(
        id=str(uuid.uuid4()),
        scan_target_id=str(target.id),
        tool_name="masscan",
        started_at=datetime.utcnow()
    )
    db.add(tool_exec)
    db.flush()

    success, raw_json, error = run_masscan(
        ip=target.ip_address,
        rate=config.masscan_rate,
        interface=config.masscan_interface,
        timeout=timeout
    )

    tool_exec.finished_at = datetime.utcnow()
    tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
    tool_exec.raw_output = raw_json
    tool_exec.raw_format = "json"
    tool_exec.error_message = error
    tool_exec.exit_code = 0 if success else 1

    if success:
        create_ports_from_masscan(db, tool_exec, target)
        target.status = TargetStatus.COMPLETED.value
    else:
        target.status = TargetStatus.FAILED.value
        target.error_message = error

    target.finished_at = datetime.utcnow()
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
        scan.progress_percent = 0.8  # Skip to 80% (masscan 10% + nmap 70%)
        db.commit()
        return

    total = len(targets_with_ports)
    completed = 0

    for target in targets_with_ports:
        try:
            scan_target_with_nmap_sequential(db, target, config)
        except Exception as e:
            # Nmap failure doesn't fail the scan, but we log the error
            logger.warning(f"Nmap service detection failed for target {target.ip_address}: {e}")
            target.error_message = f"Nmap failed: {str(e)[:200]}"
            db.commit()

        completed += 1

        # Update progress (nmap is 70% of total, from 10% to 80%)
        progress = 0.1 + (0.7 * completed / total)
        scan.progress_percent = progress
        scan.progress_updated_at = datetime.utcnow()
        db.commit()

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

    tool_exec = ToolExecution(
        id=str(uuid.uuid4()),
        scan_target_id=str(target.id),
        tool_name="nmap",
        started_at=datetime.utcnow()
    )
    db.add(tool_exec)
    db.commit()

    success, raw_xml, error = run_nmap(
        ip=target.ip_address,
        ports=port_numbers,
        nmap_args=config.nmap_args,
        timeout=timeout
    )

    tool_exec.finished_at = datetime.utcnow()
    tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
    tool_exec.raw_output = raw_xml
    tool_exec.raw_format = "xml"
    tool_exec.error_message = error
    tool_exec.exit_code = 0 if success else 1

    if success:
        update_ports_from_nmap(db, tool_exec, target)

    db.commit()


def scan_target_with_nmap_thread_safe(target_id: str, config_id: str) -> Tuple[bool, Optional[str]]:
    """
    Execute nmap for a single target with its own database session.
    DEPRECATED - kept for reference but use sequential version instead.
    """
    db = SessionLocal()
    try:
        # Load target and config in this thread's session
        target = db.query(ScanTarget).filter(ScanTarget.id == target_id).first()
        if not target:
            return False, f"Target {target_id} not found"

        from ..models import ScanConfig
        config = db.query(ScanConfig).filter(ScanConfig.id == config_id).first()
        if not config:
            return False, f"Config {config_id} not found"

        # Get open ports
        ports = db.query(Port).filter(
            Port.scan_target_id == str(target.id),
            Port.state == 'open'
        ).all()

        port_numbers = [p.port for p in ports]

        timeout = int(config.host_timeout_seconds * config.nmap_timeout_percent)
        if config.global_tool_timeout_seconds:
            timeout = config.global_tool_timeout_seconds

        tool_exec = ToolExecution(
            id=str(uuid.uuid4()),
            scan_target_id=str(target.id),
            tool_name="nmap",
            started_at=datetime.utcnow()
        )
        db.add(tool_exec)
        db.commit()

        success, raw_xml, error = run_nmap(
            ip=target.ip_address,
            ports=port_numbers,
            nmap_args=config.nmap_args,
            timeout=timeout
        )

        tool_exec.finished_at = datetime.utcnow()
        tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
        tool_exec.raw_output = raw_xml
        tool_exec.raw_format = "xml"
        tool_exec.error_message = error
        tool_exec.exit_code = 0 if success else 1

        if success:
            update_ports_from_nmap(db, tool_exec, target)

        db.commit()

        return True, None

    except Exception as e:
        db.rollback()
        return False, str(e)
    finally:
        db.close()


def scan_target_with_nmap(db, target: ScanTarget, config):
    """Execute nmap for a single target. DEPRECATED - use thread-safe version."""
    # Get open ports
    ports = db.query(Port).filter(
        Port.scan_target_id == str(target.id),
        Port.state == 'open'
    ).all()

    port_numbers = [p.port for p in ports]

    timeout = int(config.host_timeout_seconds * config.nmap_timeout_percent)
    if config.global_tool_timeout_seconds:
        timeout = config.global_tool_timeout_seconds

    tool_exec = ToolExecution(
        id=str(uuid.uuid4()),
        scan_target_id=str(target.id),
        tool_name="nmap",
        started_at=datetime.utcnow()
    )
    db.add(tool_exec)
    db.flush()

    success, raw_xml, error = run_nmap(
        ip=target.ip_address,
        ports=port_numbers,
        nmap_args=config.nmap_args,
        timeout=timeout
    )

    # Save debug output (only when DEBUG=True)
    scan_id = target.scan_id if hasattr(target, 'scan_id') else None
    save_nmap_debug(
        target=target.ip_address,
        raw_xml=raw_xml,
        scan_id=str(scan_id) if scan_id else None,
        phase="service"
    )

    tool_exec.finished_at = datetime.utcnow()
    tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
    tool_exec.raw_output = raw_xml
    tool_exec.raw_format = "xml"
    tool_exec.error_message = error
    tool_exec.exit_code = 0 if success else 1

    if success:
        update_ports_from_nmap(db, tool_exec, target)

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

        # Build command line for logging
        cmd_parts = [f"httpx -u {target_url} -json"]
        if tech_detect:
            cmd_parts.append("-td")
        if screenshots_enabled:
            cmd_parts.append("-ss")
        if vhost_discovery:
            cmd_parts.append("-vhost")

        # Create tool execution record
        tool_exec = ToolExecution(
            id=str(uuid.uuid4()),
            scan_target_id=str(target.id),
            port_id=str(port_rec.id),
            tool_name="httpx",
            command_line=" ".join(cmd_parts),
            started_at=datetime.utcnow()
        )
        db.add(tool_exec)
        db.flush()

        temp_dir = None
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

            tool_exec.finished_at = datetime.utcnow()
            tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
            tool_exec.raw_output = output.raw_json[:50000] if output.raw_json else None
            tool_exec.raw_format = "json"
            tool_exec.error_message = output.error
            tool_exec.exit_code = 0 if output.success else 1

            if output.success and output.raw_json:
                # Parse and create HttpxResult
                result = create_httpx_result_from_output(db, tool_exec, target, port_rec)
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
                    if result.virtual_hosts:
                        logger.info(f"httpx: Discovered {len(result.virtual_hosts)} virtual host(s) for {target_url}")
            else:
                # Create failed result
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
            tool_exec.finished_at = datetime.utcnow()
            tool_exec.error_message = str(e)
            tool_exec.exit_code = 1
            db.commit()
        finally:
            # Cleanup temp directory from httpx if it exists
            if output and output.screenshot_path:
                temp_dir = output.screenshot_path.parent.parent
                if temp_dir and temp_dir.exists() and 'httpx_' in str(temp_dir):
                    try:
                        shutil.rmtree(str(temp_dir))
                    except Exception as cleanup_err:
                        logger.debug(f"Failed to cleanup temp dir: {cleanup_err}")

        completed += 1

        # Update progress (httpx is 5% of total, from 75% to 80%)
        progress = 0.75 + (0.05 * completed / total)
        scan.progress_percent = progress
        scan.progress_updated_at = datetime.utcnow()
        db.commit()

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

        # Build command line for logging
        cmd_line = f"katana -u {target_url} -d {max_depth} -c {concurrency} -rate-limit {rate_limit} -timeout {timeout} -jsonl"

        # Create tool execution record
        tool_exec = ToolExecution(
            id=str(uuid.uuid4()),
            scan_target_id=str(target.id),
            port_id=str(port_rec.id),
            tool_name="katana",
            command_line=cmd_line,
            started_at=datetime.utcnow()
        )
        db.add(tool_exec)
        db.flush()

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

            tool_exec.finished_at = datetime.utcnow()
            tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
            tool_exec.error_message = output.error
            tool_exec.exit_code = 0 if output.success else 1

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

                # Store truncated version in raw_output for quick access
                tool_exec.raw_output = output.raw_output[:50000] if len(output.raw_output) > 50000 else output.raw_output
            tool_exec.raw_format = "jsonl"

            if output.success and output.endpoints:
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
            else:
                logger.warning(f"Katana crawl failed for {target_url}: {output.error}")

            db.commit()

        except Exception as e:
            logger.error(f"Katana error for {target_url}: {e}")
            tool_exec.finished_at = datetime.utcnow()
            tool_exec.error_message = str(e)
            tool_exec.exit_code = 1
            db.commit()

        completed += 1

        # Update progress (katana is 2% of total, from 78% to 80%)
        progress = 0.78 + (0.02 * completed / total)
        scan.progress_percent = progress
        scan.progress_updated_at = datetime.utcnow()
        db.commit()

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
        scan.progress_percent = 0.9  # Skip to 90%
        db.commit()
        return

    total = len(ssh_port_records)
    completed = 0

    # SSH-audit is fast, so we can run serially or in small batches
    # For simplicity, run serially (parallel would be similar to nmap)
    for port_record in ssh_port_records:
        # Get target for this port
        target = db.query(ScanTarget).filter(
            ScanTarget.id == port_record.scan_target_id
        ).first()

        if not target:
            continue

        # Create tool execution record
        tool_exec = ToolExecution(
            id=str(uuid.uuid4()),
            scan_target_id=str(target.id),
            tool_name="ssh-audit",
            started_at=datetime.utcnow()
        )
        db.add(tool_exec)
        db.flush()

        # Run ssh-audit
        # Use 60s timeout (ssh-audit is usually fast)
        timeout = 60
        if config.global_tool_timeout_seconds:
            timeout = config.global_tool_timeout_seconds

        success, raw_json, error = run_ssh_audit(
            ip=target.ip_address,
            port=port_record.port,
            timeout=timeout
        )

        # Save debug output (only when DEBUG=True)
        save_ssh_audit_debug(
            target=target.ip_address,
            raw_json=raw_json,
            scan_id=str(scan.id),
            port=port_record.port
        )

        # Update tool execution
        tool_exec.finished_at = datetime.utcnow()
        tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
        tool_exec.raw_output = raw_json
        tool_exec.raw_format = "json"
        tool_exec.error_message = error
        tool_exec.exit_code = 0 if success else 1

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

        completed += 1

        # Update scan progress (ssh-audit is 10% of total, from 80% to 90%)
        progress = 0.8 + (0.1 * completed / total)
        scan.progress_percent = progress
        scan.progress_updated_at = datetime.utcnow()
        db.commit()

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
        scan.progress_percent = 1.0
        db.commit()
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
        scan.progress_percent = 1.0
        db.commit()
        return

    total = len(scannable_ports)
    scanned = 0
    skipped = 0
    vulns_found = 0

    logger.info(f"Nuclei: {total} scannable ports from {len(all_ports)} total open ports")

    for port_rec, profile, httpx_result in scannable_ports:
        target = db.query(ScanTarget).filter(
            ScanTarget.id == port_rec.scan_target_id
        ).first()

        if not target:
            skipped += 1
            continue

        ip = target.ip_address
        port = port_rec.port

        # Validate tags have templates (skip if no templates found)
        if profile.tags:
            has_templates, template_count = validate_tags(profile.tags)
            if not has_templates:
                logger.warning(f"No templates found for tags {profile.tags} on {ip}:{port}, skipping")
                skipped += 1
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

        # Create tool execution record - show actual command that will run
        if profile.tags:
            cmd_line = f"nuclei -u {nuclei_target} -tags {','.join(profile.tags)}"
        else:
            cmd_line = f"nuclei -u {nuclei_target} (comprehensive - no tag filter)"
        tool_exec = ToolExecution(
            id=str(uuid.uuid4()),
            scan_target_id=str(target.id),
            port_id=str(port_rec.id),  # Link ToolExecution directly to Port
            tool_name="nuclei",
            command_line=cmd_line,
            started_at=datetime.utcnow()
        )
        db.add(tool_exec)
        db.flush()

        try:
            # Calculate timeout with profile multiplier
            base_timeout = config.nuclei_timeout or 300
            if config.global_tool_timeout_seconds:
                base_timeout = config.global_tool_timeout_seconds
            timeout = int(base_timeout * profile.timeout_multiplier)

            # Use profile-specific rate limit or default
            rate_limit = profile.rate_limit or 150

            success, raw_jsonl, error = run_nuclei(
                target=nuclei_target,
                severity=config.nuclei_severity or "critical,high,medium,low,info",
                templates=config.nuclei_templates,
                tags=profile.tags if profile.tags else None,  # None = comprehensive (no tag filter)
                timeout=timeout,
                rate_limit=rate_limit,
                exclude_templates=excluded_templates
            )

            # Save debug output (only when DEBUG=True)
            save_nuclei_debug(
                target=ip,
                raw_jsonl=raw_jsonl,
                scan_id=str(scan.id),
                port=port
            )

            # Update tool execution
            tool_exec.finished_at = datetime.utcnow()
            tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
            tool_exec.raw_format = "jsonl"
            tool_exec.error_message = error
            tool_exec.exit_code = 0 if success else 1

            if success:
                # IMPORTANT: Set full raw_output BEFORE parsing, then truncate AFTER
                # Parser reads from tool_exec.raw_output, so we need full data first
                tool_exec.raw_output = raw_jsonl if raw_jsonl else None

                # Parse and create Vulnerability records (pass port_rec for direct linking)
                vulns = create_vulnerabilities_from_nuclei(
                    db, tool_exec, target, port_rec,
                    discovery_source='port'  # Explicit: per-port nuclei scanning
                )
                vulns_found += len(vulns)

                # Log observability info
                logger.info(f"Nuclei output: {len(raw_jsonl) if raw_jsonl else 0} bytes, parsed {len(vulns)} vulnerabilities for {nuclei_target}")

                # Now truncate for storage (parsing already complete on full data)
                tool_exec.raw_output = raw_jsonl[:50000] if raw_jsonl else None

                # Update scan vulnerability count
                scan.total_vulnerabilities += len(vulns)
            else:
                tool_exec.raw_output = raw_jsonl[:50000] if raw_jsonl else None

            db.commit()
            scanned += 1

        except Exception as e:
            logger.error(f"Nuclei error for {nuclei_target}: {e}")
            tool_exec.finished_at = datetime.utcnow()
            tool_exec.error_message = str(e)
            tool_exec.exit_code = 1
            db.commit()
            skipped += 1

        # Update scan progress (nuclei is 10% of total, from 90% to 100%)
        progress = 0.9 + (0.1 * (scanned + skipped) / total)
        scan.progress_percent = progress
        scan.progress_updated_at = datetime.utcnow()
        db.commit()

    logger.info(f"Nuclei complete: {scanned} scanned, {skipped} skipped, {vulns_found} vulnerabilities found")


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
        scan.progress_percent = 0.91
        db.commit()
        return

    # Get excluded templates
    excluded_templates = get_excluded_templates()

    # Group endpoints by host (target)
    endpoints_by_target = {}
    for endpoint in endpoints:
        # Find the scan target for this endpoint's host
        target = None
        for t in targets:
            if t.ip_address in endpoint.url or endpoint.host == t.ip_address:
                target = t
                break

        if target:
            if target.id not in endpoints_by_target:
                endpoints_by_target[target.id] = {'target': target, 'urls': []}
            # Cap at 500 endpoints per host for safety
            if len(endpoints_by_target[target.id]['urls']) < 500:
                endpoints_by_target[target.id]['urls'].append(endpoint.url)

    total_targets = len(endpoints_by_target)
    if total_targets == 0:
        logger.info("No endpoints matched to scan targets")
        scan.progress_percent = 0.91
        db.commit()
        return

    scanned = 0
    vulns_found = 0

    logger.info(f"Nuclei endpoints: {len(endpoints)} total endpoints across {total_targets} targets")

    for target_id, data in endpoints_by_target.items():
        target = data['target']
        urls = data['urls']

        logger.info(f"Nuclei endpoints: scanning {len(urls)} URLs for {target.ip_address}")

        # Write URLs to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for url in urls:
                f.write(url + '\n')
            urls_file = f.name

        try:
            # Create tool execution record
            tool_exec = ToolExecution(
                id=str(uuid.uuid4()),
                scan_target_id=str(target.id),
                port_id=None,  # No specific port for endpoint scanning
                tool_name="nuclei-endpoints",
                command_line=f"nuclei -list <{len(urls)} urls> -tags http,cve,exposure,misconfig,tech",
                started_at=datetime.utcnow()
            )
            db.add(tool_exec)
            db.flush()

            # Get timeout from config
            timeout = getattr(config, 'nuclei_endpoint_timeout', 600) or 600
            if config.global_tool_timeout_seconds:
                timeout = config.global_tool_timeout_seconds

            # Get severity from config
            severity_list = getattr(config, 'nuclei_endpoint_severity', ['critical', 'high', 'medium']) or ['critical', 'high', 'medium']
            severity = ','.join(severity_list) if isinstance(severity_list, list) else severity_list

            success, raw_jsonl, error = run_nuclei_list(
                urls_file=urls_file,
                severity=severity,
                tags=['http', 'cve', 'exposure', 'misconfig', 'tech'],
                timeout=timeout,
                rate_limit=50,  # Conservative rate limit for safety
                exclude_templates=excluded_templates
            )

            # Update tool execution
            tool_exec.finished_at = datetime.utcnow()
            tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
            tool_exec.raw_format = "jsonl"
            tool_exec.error_message = error
            tool_exec.exit_code = 0 if success else 1

            if success:
                # Set raw output for parser
                tool_exec.raw_output = raw_jsonl if raw_jsonl else None

                # Parse and create Vulnerability records with discovery_source='endpoint'
                vulns = create_vulnerabilities_from_nuclei(
                    db, tool_exec, target,
                    port_rec=None,
                    discovery_source='endpoint'
                )
                vulns_found += len(vulns)

                logger.info(f"Nuclei endpoints: {len(raw_jsonl) if raw_jsonl else 0} bytes output, {len(vulns)} vulnerabilities for {target.ip_address}")

                # Truncate for storage
                tool_exec.raw_output = raw_jsonl[:50000] if raw_jsonl else None

                # Update scan vulnerability count
                scan.total_vulnerabilities += len(vulns)
            else:
                tool_exec.raw_output = raw_jsonl[:50000] if raw_jsonl else None

            db.commit()
            scanned += 1

        except Exception as e:
            logger.error(f"Nuclei endpoints error for {target.ip_address}: {e}")
            tool_exec.finished_at = datetime.utcnow()
            tool_exec.error_message = str(e)
            tool_exec.exit_code = 1
            db.commit()

        finally:
            # Cleanup temp file
            import os
            if os.path.exists(urls_file):
                os.unlink(urls_file)

        # Update progress (88% -> 91% range)
        progress = 0.88 + (0.03 * scanned / total_targets)
        scan.progress_percent = progress
        scan.progress_updated_at = datetime.utcnow()
        db.commit()

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

        # Create tool execution record
        tool_exec = ToolExecution(
            id=str(uuid.uuid4()),
            scan_target_id=str(target.id),
            port_id=str(port_record.id),
            tool_name="nmap-nse",
            command_line=f"nmap -p{port} --script={','.join(scripts)} {ip}",
            started_at=datetime.utcnow()
        )
        db.add(tool_exec)
        db.flush()

        try:
            # Run NSE scripts
            success, raw_xml, error = run_nmap_nse(
                ip=ip,
                port=port,
                scripts=scripts,
                protocol=protocol,
                timeout=timeout
            )

            tool_exec.finished_at = datetime.utcnow()
            tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
            tool_exec.raw_output = raw_xml[:50000] if raw_xml else None
            tool_exec.raw_format = "xml"
            tool_exec.error_message = error
            tool_exec.exit_code = 0 if success else 1

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
            tool_exec.finished_at = datetime.utcnow()
            tool_exec.error_message = str(e)
            tool_exec.exit_code = 1
            db.commit()

        completed += 1

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

        # Create tool execution record
        tool_exec = ToolExecution(
            id=str(uuid.uuid4()),
            scan_target_id=str(target.id),
            port_id=str(port_record.id),
            tool_name="sslscan",
            command_line=f"sslscan {ip}:{port}",
            started_at=datetime.utcnow()
        )
        db.add(tool_exec)
        db.flush()

        try:
            # Run sslscan
            success, raw_xml, error = run_sslscan(
                ip=ip,
                port=port,
                timeout=60,
                connect_timeout=10
            )

            tool_exec.finished_at = datetime.utcnow()
            tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
            tool_exec.raw_output = raw_xml[:50000] if raw_xml else None
            tool_exec.raw_format = "xml"
            tool_exec.error_message = error
            tool_exec.exit_code = 0 if success else 1

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
            tool_exec.finished_at = datetime.utcnow()
            tool_exec.error_message = str(e)
            tool_exec.exit_code = 1
            db.commit()

        completed += 1

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
    timeout = getattr(config, 'testssl_timeout', 300)

    total = len(tls_ports)
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

        # Build command line for logging
        cmd_line = f"testssl --fast --jsonfile=output.json {host}:{port}"

        # Create tool execution record
        tool_exec = ToolExecution(
            id=str(uuid.uuid4()),
            scan_target_id=str(target.id),
            port_id=str(port_record.id),
            tool_name="testssl",
            command_line=cmd_line,
            started_at=datetime.utcnow()
        )
        db.add(tool_exec)
        db.flush()

        try:
            # Run testssl.sh
            output = run_testssl(
                host=host,
                port=port,
                timeout=timeout,
                fast_mode=True
            )

            tool_exec.finished_at = datetime.utcnow()
            tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
            tool_exec.exit_code = 0 if output.success else 1
            tool_exec.error_message = output.error

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

                    # Store truncated raw output in tool execution
                    if output.raw_json:
                        tool_exec.raw_output = output.raw_json[:50000] if len(output.raw_json) > 50000 else output.raw_json

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
            tool_exec.finished_at = datetime.utcnow()
            tool_exec.error_message = str(e)
            tool_exec.exit_code = 1
            db.commit()

        completed += 1

        # Update progress
        progress = 0.96 + (completed / total) * 0.01  # 96% -> 97%
        scan.progress_percent = progress
        scan.progress_updated_at = datetime.utcnow()
        db.commit()

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

            # Create tool execution record
            cmd_line = f"nikto -h {ip} -p {port} -Format json"
            if ssl:
                cmd_line += " -ssl"

            tool_exec = ToolExecution(
                id=str(uuid.uuid4()),
                scan_target_id=str(target.id),
                port_id=str(port_rec.id),
                tool_name="nikto",
                command_line=cmd_line,
                started_at=datetime.utcnow()
            )
            db.add(tool_exec)
            db.flush()

            try:
                # Run Nikto
                timeout = config.nikto_timeout or 120
                success, raw_json, error = run_nikto(
                    target=ip,
                    port=port,
                    timeout=timeout,
                    ssl=ssl
                )

                tool_exec.finished_at = datetime.utcnow()
                tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
                tool_exec.raw_output = raw_json[:50000] if raw_json else None  # Truncate if needed
                tool_exec.raw_format = "json"
                tool_exec.error_message = error
                tool_exec.exit_code = 0 if success else 1

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

                db.commit()
                total_scanned += 1

            except Exception as e:
                logger.error(f"Nikto error for {ip}:{port}: {e}")
                tool_exec.finished_at = datetime.utcnow()
                tool_exec.error_message = str(e)
                tool_exec.exit_code = 1
                db.commit()

    # Update scan statistics
    from ..models.vulnerability import Vulnerability
    total_vulns = db.query(Vulnerability).join(ScanTarget).filter(
        ScanTarget.scan_id == str(scan.id)
    ).count()
    scan.total_vulnerabilities = total_vulns
    db.commit()

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

            # Create tool execution record
            tool_exec = ToolExecution(
                id=str(uuid.uuid4()),
                scan_target_id=str(target.id),
                port_id=str(port_rec.id),
                tool_name="zap",
                command_line=f"zap-baseline {target_url}",
                started_at=datetime.utcnow()
            )
            db.add(tool_exec)
            db.flush()

            try:
                # Run ZAP baseline scan
                timeout = config.zap_timeout or 300
                success, alerts_json, error = run_zap_baseline(
                    target_url=target_url,
                    timeout=timeout,
                    spider_timeout=60
                )

                tool_exec.finished_at = datetime.utcnow()
                tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
                tool_exec.raw_output = alerts_json[:50000] if alerts_json else None  # Truncate if needed
                tool_exec.raw_format = "json"
                tool_exec.error_message = error
                tool_exec.exit_code = 0 if success else 1

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

                db.commit()
                total_scanned += 1

            except Exception as e:
                logger.error(f"ZAP error for {target_url}: {e}")
                tool_exec.finished_at = datetime.utcnow()
                tool_exec.error_message = str(e)
                tool_exec.exit_code = 1
                db.commit()

    # Update scan statistics
    from ..models.vulnerability import Vulnerability
    total_vulns = db.query(Vulnerability).join(ScanTarget).filter(
        ScanTarget.scan_id == str(scan.id)
    ).count()
    scan.total_vulnerabilities = total_vulns
    db.commit()

    logger.info(f"ZAP complete: {total_scanned} ports scanned, {total_findings} findings")
