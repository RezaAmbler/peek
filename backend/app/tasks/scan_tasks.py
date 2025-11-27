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
from ..tools.nuclei import run_nuclei
from ..parsers.masscan_parser import create_ports_from_masscan
from ..parsers.nmap_discovery_parser import create_ports_from_nmap_discovery
from ..parsers.nmap_parser import update_ports_from_nmap
from ..parsers.ssh_audit_parser import create_ssh_audit_from_output
from ..parsers.nuclei_parser import create_vulnerabilities_from_nuclei
from ..services.service_profile import get_nuclei_profile, build_nuclei_target
from sqlalchemy import select
import uuid
import logging

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

    Phase 1: Run masscan on all targets (10% progress)
    Phase 2: Run nmap on targets with open ports (70% progress)
    Phase 3: Run ssh-audit (Phase 2D)
    Phase 4: Run nuclei (Phase 2E)
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

            # Phase 2: Nmap (10% -> 80%)
            scan.current_phase = ScanPhase.NMAP.value
            db.commit()
            self.update_state(state='PROGRESS', meta={'phase': 'nmap', 'progress': 0.1})
            run_nmap_phase(db, scan, targets, config)

            # Phase 3: SSH-Audit (80% -> 90%)
            if config.enable_ssh_audit:
                scan.current_phase = ScanPhase.SSH_AUDIT.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'ssh-audit', 'progress': 0.8})
                run_ssh_audit_phase(db, scan, targets, config)

            # Phase 4: Nuclei (90% -> 100%)
            if config.enable_nuclei:
                scan.current_phase = ScanPhase.NUCLEI.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'nuclei', 'progress': 0.9})
                run_nuclei_phase(db, scan, targets, config)

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

    # Use nmap discovery with top 1000 ports (covers most common services)
    # This is more reliable in Docker than masscan's full port scan
    success, raw_xml, error = run_nmap_discovery(
        ip=target.ip_address,
        scan_top_ports=1000,  # Top 1000 most common ports
        timing_template="T4",  # Fast timing
        timeout=timeout
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
            # Nmap failure doesn't fail the target, just logs
            pass

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

    tool_exec.finished_at = datetime.utcnow()
    tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
    tool_exec.raw_output = raw_xml
    tool_exec.raw_format = "xml"
    tool_exec.error_message = error
    tool_exec.exit_code = 0 if success else 1

    if success:
        update_ports_from_nmap(db, tool_exec, target)

    db.commit()

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

    # Filter ports that have scannable profiles
    scannable_ports = []
    for port_rec in all_ports:
        profile = get_nuclei_profile(
            service_name=port_rec.service_name,
            product=port_rec.product,
            version=port_rec.version
        )
        if profile.should_scan:
            scannable_ports.append((port_rec, profile))

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

    for port_rec, profile in scannable_ports:
        target = db.query(ScanTarget).filter(
            ScanTarget.id == port_rec.scan_target_id
        ).first()

        if not target:
            skipped += 1
            continue

        ip = target.ip_address
        port = port_rec.port

        # Build target string based on profile
        nuclei_target = build_nuclei_target(ip, port, profile)
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

            success, raw_jsonl, error = run_nuclei(
                target=nuclei_target,
                severity=config.nuclei_severity or "critical,high,medium",
                templates=config.nuclei_templates,
                tags=profile.tags if profile.tags else None,  # None = comprehensive (no tag filter)
                timeout=timeout
            )

            # Update tool execution
            tool_exec.finished_at = datetime.utcnow()
            tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
            tool_exec.raw_output = raw_jsonl[:50000] if raw_jsonl else None
            tool_exec.raw_format = "jsonl"
            tool_exec.error_message = error
            tool_exec.exit_code = 0 if success else 1

            if success:
                # Parse and create Vulnerability records
                vulns = create_vulnerabilities_from_nuclei(db, tool_exec, target)
                vulns_found += len(vulns)

                # Update scan vulnerability count
                scan.total_vulnerabilities += len(vulns)

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
