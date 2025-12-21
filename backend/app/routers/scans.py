from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, delete
from typing import Optional
from datetime import datetime
import uuid
from ..database import get_db
from ..models import Scan, ScanTarget, ScanConfig, User, ScanStatus, Port, SSHAudit, Vulnerability, NseFinding, SslScanResult
from ..models.httpx_result import HttpxResult
from ..schemas.scan import (
    ScanCreate,
    ScanUpdate,
    ScanResponse,
    ScanDetailResponse,
    ScanListResponse,
)
from ..routers.auth import get_current_user

router = APIRouter()


async def get_next_run_number(db: AsyncSession, config_id: str) -> int:
    """Get the next run number for a config."""
    result = await db.execute(
        select(func.max(Scan.run_number)).where(Scan.config_id == config_id)
    )
    max_run = result.scalar()
    return (max_run or 0) + 1


def generate_scan_name(run_number: int, created_at: datetime) -> str:
    """Generate default scan name if not provided."""
    return f"Run #{run_number} — {created_at.strftime('%b %d, %Y %H:%M')}"

@router.get("", response_model=ScanListResponse, summary="List all scans")
async def list_scans(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    status: Optional[str] = Query(None, description="Filter by status: pending, queued, running, completed, failed, cancelled"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List all scans for the current user with pagination and optional status filter."""
    # Base query - user sees their own scans
    # NOTE: Phase 5+ will add organization_id filtering here
    query = select(Scan).where(Scan.user_id == current_user.id)

    # Filter by status if provided
    if status:
        query = query.where(Scan.status == status)

    # Get total count
    count_query = select(func.count(Scan.id)).where(Scan.user_id == current_user.id)
    if status:
        count_query = count_query.where(Scan.status == status)
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    # Apply pagination and ordering
    query = query.order_by(Scan.created_at.desc()).offset((page - 1) * limit).limit(limit)

    result = await db.execute(query)
    scans = result.scalars().all()

    # Fetch config names for all scans
    config_ids = list(set(s.config_id for s in scans if s.config_id))
    config_names = {}
    if config_ids:
        configs_result = await db.execute(
            select(ScanConfig.id, ScanConfig.name).where(ScanConfig.id.in_(config_ids))
        )
        config_names = {str(row[0]): row[1] for row in configs_result}

    # Build response with config_name included
    scan_responses = []
    for scan in scans:
        scan_responses.append(ScanResponse(
            id=scan.id,
            user_id=scan.user_id,
            created_by_id=scan.created_by_id,
            config_id=scan.config_id,
            config_name=config_names.get(str(scan.config_id), ""),
            run_number=scan.run_number,
            name=scan.name,
            description=scan.description,
            status=scan.status,
            current_phase=scan.current_phase,
            created_at=scan.created_at,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            progress_percent=scan.progress_percent,
            total_targets=scan.total_targets,
            completed_targets=scan.completed_targets,
            failed_targets=scan.failed_targets,
            total_open_ports=scan.total_open_ports,
            total_vulnerabilities=scan.total_vulnerabilities,
        ))

    return ScanListResponse(
        scans=scan_responses,
        total=total,
        page=page,
        pages=(total + limit - 1) // limit
    )

@router.get("/{scan_id}", response_model=ScanDetailResponse, summary="Get scan details")
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get detailed information about a specific scan including its targets."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Authorization: owner or admin
    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Load targets
    targets_result = await db.execute(
        select(ScanTarget)
        .where(ScanTarget.scan_id == scan_id)
        .order_by(ScanTarget.sequence)
    )
    targets = targets_result.scalars().all()

    return ScanDetailResponse(
        **{c.name: getattr(scan, c.name) for c in scan.__table__.columns},
        targets=targets
    )

@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED, summary="Create a new scan")
async def create_scan(
    scan_data: ScanCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new scan run from a configuration.

    Targets are inherited from the config — they are copied to ScanTarget rows at scan creation.
    The scan is created in **pending** status. Call `POST /api/scans/{id}/start` to queue it for execution.
    """
    # Verify config exists and user has access
    config_id_str = str(scan_data.config_id)
    config_result = await db.execute(
        select(ScanConfig).where(ScanConfig.id == config_id_str)
    )
    config = config_result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")

    if config.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to use this configuration")

    # Validate config has targets
    if not config.targets or len(config.targets) == 0:
        raise HTTPException(
            status_code=400,
            detail="Configuration has no targets. Add targets to the config before creating a scan."
        )

    # Get next run number for this config
    run_number = await get_next_run_number(db, config_id_str)

    # Create scan
    created_at = datetime.utcnow()
    scan = Scan(
        user_id=current_user.id,
        created_by_id=current_user.id,
        organization_id=None,  # Phase 1-4: always NULL
        config_id=config_id_str,
        run_number=run_number,
        name=scan_data.name or generate_scan_name(run_number, created_at),
        description=scan_data.description,
        created_at=created_at,
        total_targets=len(config.targets)
    )
    db.add(scan)
    await db.flush()  # Get scan.id

    # Create targets from config.targets
    for idx, target_ip in enumerate(config.targets):
        scan_target = ScanTarget(
            scan_id=scan.id,
            ip_address=target_ip.strip(),
            device_name=None,  # Could add device_name mapping in config later
            sequence=idx
        )
        db.add(scan_target)

    await db.commit()
    await db.refresh(scan)

    # Return with config_name for display
    response = ScanResponse(
        id=scan.id,
        user_id=scan.user_id,
        created_by_id=scan.created_by_id,
        config_id=scan.config_id,
        config_name=config.name,
        run_number=scan.run_number,
        name=scan.name,
        description=scan.description,
        status=scan.status,
        current_phase=scan.current_phase,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        progress_percent=scan.progress_percent,
        total_targets=scan.total_targets,
        completed_targets=scan.completed_targets,
        failed_targets=scan.failed_targets,
        total_open_ports=scan.total_open_ports,
        total_vulnerabilities=scan.total_vulnerabilities,
    )
    return response

@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete a scan"""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Authorization: owner or admin
    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Cannot delete running scans
    if scan.status == ScanStatus.RUNNING.value:
        raise HTTPException(status_code=400, detail="Cannot delete a running scan")

    await db.delete(scan)
    await db.commit()

@router.patch("/{scan_id}", response_model=ScanResponse)
async def update_scan(
    scan_id: str,
    scan_update: ScanUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update scan metadata (name, description only). Config and targets cannot be changed after creation."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Authorization: owner or admin
    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Only allow editing pending scans
    if scan.status != ScanStatus.PENDING.value:
        raise HTTPException(
            status_code=400,
            detail="Cannot edit scan that is not in pending status"
        )

    # Update only name and description
    update_data = scan_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(scan, field, value)

    await db.commit()
    await db.refresh(scan)

    return scan

@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Cancel a running or pending scan"""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    if scan.status not in [ScanStatus.PENDING.value, ScanStatus.QUEUED.value, ScanStatus.RUNNING.value]:
        raise HTTPException(status_code=400, detail="Scan is not running or pending")

    # TODO: Phase 2B - Actually cancel Celery task using scan.celery_task_id

    scan.status = ScanStatus.CANCELLED.value
    await db.commit()
    await db.refresh(scan)

    return scan

@router.post("/{scan_id}/start", response_model=ScanResponse, summary="Start a scan")
async def start_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Queue a pending scan for execution.

    The scan will be picked up by the Celery worker and progress through:
    **queued** → **running** → **completed** (or **failed**)
    """
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    if scan.status != ScanStatus.PENDING.value:
        raise HTTPException(status_code=400, detail="Scan is not in pending status")

    # Queue Celery task
    from ..tasks.scan_tasks import run_scan
    task = run_scan.delay(str(scan.id))
    scan.celery_task_id = task.id
    scan.status = ScanStatus.QUEUED.value

    await db.commit()
    await db.refresh(scan)

    return scan


@router.post("/{scan_id}/restart", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def restart_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Restart a failed/completed/cancelled scan by creating a new run of the same configuration.

    Creates a new scan with:
    - Next run_number for the config
    - Auto-generated name (or with " (retry)" suffix if original had custom name)
    - Same configuration
    - Fresh targets from config
    - Automatically starts the new scan

    Returns the new scan object.
    """
    # Get original scan with config
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    original_scan = result.scalar_one_or_none()

    if not original_scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if original_scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Only allow restarting non-running scans
    if original_scan.status in [ScanStatus.RUNNING.value, ScanStatus.QUEUED.value]:
        raise HTTPException(
            status_code=400,
            detail="Cannot restart a scan that is currently running or queued"
        )

    # Get config to get current targets
    config_result = await db.execute(
        select(ScanConfig).where(ScanConfig.id == original_scan.config_id)
    )
    config = config_result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")

    if not config.targets or len(config.targets) == 0:
        raise HTTPException(
            status_code=400,
            detail="Configuration has no targets. Add targets before restarting."
        )

    # Get next run number
    run_number = await get_next_run_number(db, original_scan.config_id)

    # Create new scan name
    created_at = datetime.utcnow()
    if original_scan.name and not original_scan.name.startswith("Run #"):
        # Custom name - add retry suffix
        new_name = original_scan.name
        if not new_name.endswith(" (retry)"):
            new_name = f"{new_name} (retry)"
    else:
        # Auto-generated name
        new_name = generate_scan_name(run_number, created_at)

    # Create new scan
    new_scan = Scan(
        user_id=current_user.id,
        created_by_id=current_user.id,
        organization_id=original_scan.organization_id,
        config_id=original_scan.config_id,
        run_number=run_number,
        name=new_name,
        description=original_scan.description,
        created_at=created_at,
        total_targets=len(config.targets)
    )
    db.add(new_scan)
    await db.flush()  # Get new_scan.id

    # Create targets from config (fresh copy)
    for idx, target_ip in enumerate(config.targets):
        new_target = ScanTarget(
            scan_id=new_scan.id,
            ip_address=target_ip.strip(),
            device_name=None,
            sequence=idx
        )
        db.add(new_target)

    await db.commit()
    await db.refresh(new_scan)

    # Automatically start the new scan
    from ..tasks.scan_tasks import run_scan
    task = run_scan.delay(str(new_scan.id))
    new_scan.celery_task_id = task.id
    new_scan.status = ScanStatus.QUEUED.value

    await db.commit()
    await db.refresh(new_scan)

    return new_scan


@router.get("/{scan_id}/comparable", summary="Get comparable scans")
async def get_comparable_scans(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get scans that can be compared with this one (same config_id).

    Only completed scans from the same configuration are returned,
    as meaningful comparisons require the same targets and scan settings.
    """
    # Get current scan
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Get config for display
    config_result = await db.execute(
        select(ScanConfig).where(ScanConfig.id == scan.config_id)
    )
    config = config_result.scalar_one_or_none()

    # Get comparable scans (same config, completed, not self)
    comparable_result = await db.execute(
        select(Scan)
        .where(
            Scan.config_id == scan.config_id,
            Scan.id != scan_id,
            Scan.status == "completed"
        )
        .order_by(Scan.created_at.desc())
    )
    comparable_scans = comparable_result.scalars().all()

    return {
        "current_scan": {
            "id": scan.id,
            "name": scan.name,
            "run_number": scan.run_number,
            "config_id": scan.config_id,
            "config_name": config.name if config else None,
            "status": scan.status,
            "created_at": scan.created_at.isoformat(),
            "total_targets": scan.total_targets
        },
        "comparable_scans": [
            {
                "id": s.id,
                "name": s.name,
                "run_number": s.run_number,
                "status": s.status,
                "created_at": s.created_at.isoformat(),
                "total_targets": s.total_targets,
                "total_open_ports": s.total_open_ports,
                "total_vulnerabilities": s.total_vulnerabilities
            }
            for s in comparable_scans
        ],
        "total_comparable": len(comparable_scans)
    }


@router.get("/{scan_id}/ports", summary="Get discovered ports")
async def get_scan_ports(
    scan_id: str,
    state: Optional[str] = Query("open", description="Filter by port state: open, filtered, closed, or 'all' for no filter"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get ports discovered during the scan, including service and version info from nmap.

    By default, only **open** ports are returned. Use `state=all` to see filtered/closed ports.
    """
    # Verify scan access
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Build query with optional state filter
    ports_query = select(Port).join(ScanTarget).where(
        ScanTarget.scan_id == scan_id
    )

    # Filter by state (default: only open ports)
    if state and state.lower() != "all":
        ports_query = ports_query.where(Port.state == state.lower())

    ports_query = ports_query.order_by(ScanTarget.ip_address, Port.port)

    ports_result = await db.execute(ports_query)
    ports = ports_result.scalars().all()

    # Join with target info
    result_list = []
    for port in ports:
        target_result = await db.execute(
            select(ScanTarget).where(ScanTarget.id == port.scan_target_id)
        )
        target = target_result.scalar_one()

        result_list.append({
            "id": str(port.id),
            "ip_address": target.ip_address,
            "device_name": target.device_name,
            "port": port.port,
            "protocol": port.protocol,
            "state": port.state,
            "service_name": port.service_name,
            "product": port.product,
            "version": port.version,
            "discovered_by": port.discovered_by
        })

    return result_list

@router.get("/{scan_id}/ssh-audits")
async def get_scan_ssh_audits(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all SSH audit results for a scan"""
    # Verify scan access
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Get all SSH audits for this scan
    query = (
        select(SSHAudit)
        .join(Port, SSHAudit.port_id == Port.id)
        .join(ScanTarget, Port.scan_target_id == ScanTarget.id)
        .where(ScanTarget.scan_id == scan_id)
    )

    audits_result = await db.execute(query)
    audits = audits_result.scalars().all()

    # Join with port and target info
    result_list = []
    for audit in audits:
        port_result = await db.execute(
            select(Port).where(Port.id == audit.port_id)
        )
        port = port_result.scalar_one()

        target_result = await db.execute(
            select(ScanTarget).where(ScanTarget.id == port.scan_target_id)
        )
        target = target_result.scalar_one()

        result_list.append({
            "id": str(audit.id),
            "ip_address": target.ip_address,
            "device_name": target.device_name,
            "port": port.port,
            "banner": audit.banner,
            "ssh_version": audit.ssh_version,
            "key_exchange_algorithms": audit.key_exchange_algorithms,
            "host_key_algorithms": audit.host_key_algorithms,
            "encryption_algorithms": audit.encryption_algorithms,
            "mac_algorithms": audit.mac_algorithms,
            "vulnerabilities": audit.vulnerabilities,
            "recommendations": audit.recommendations,
            "connection_failed": audit.connection_failed,
            "failure_reason": audit.failure_reason
        })

    return result_list

@router.get("/{scan_id}/vulnerabilities", summary="Get vulnerabilities")
async def get_scan_vulnerabilities(
    scan_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity: critical,high,medium,low,info (comma-separated)"),
    source_tool: Optional[str] = Query(None, description="Filter by source tool: nuclei,nikto,zap,nse (comma-separated)"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all vulnerabilities found during the scan, sorted by severity. Supports filtering by tool (nuclei, nikto, zap, nse)."""
    # Verify scan access
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Build query
    query = (
        select(Vulnerability)
        .join(ScanTarget, Vulnerability.scan_target_id == ScanTarget.id)
        .where(ScanTarget.scan_id == scan_id)
    )

    # Filter by severity if provided
    if severity:
        severities = [s.strip() for s in severity.split(',')]
        query = query.where(Vulnerability.severity.in_(severities))

    # Filter by source tool if provided
    if source_tool:
        tools = [t.strip() for t in source_tool.split(',')]
        query = query.where(Vulnerability.source_tool.in_(tools))

    # Order by severity (critical first)
    severity_order = {
        'critical': 1,
        'high': 2,
        'medium': 3,
        'low': 4,
        'info': 5
    }

    vulns_result = await db.execute(query)
    vulns = vulns_result.scalars().all()

    # Sort by severity
    sorted_vulns = sorted(vulns, key=lambda v: severity_order.get(v.severity, 99))

    # Join with target info
    result_list = []
    for vuln in sorted_vulns:
        target_result = await db.execute(
            select(ScanTarget).where(ScanTarget.id == vuln.scan_target_id)
        )
        target = target_result.scalar_one()

        result_list.append({
            "id": str(vuln.id),
            "ip_address": target.ip_address,
            "device_name": target.device_name,
            "template_id": vuln.template_id,
            "name": vuln.name,
            "severity": vuln.severity,
            "type": vuln.vuln_type,
            "matched_at": vuln.matched_at,
            "host": vuln.host,
            "port": vuln.port,
            "source_tool": vuln.source_tool,
            "description": vuln.description,
            "reference": vuln.reference,
            "tags": vuln.tags,
            "extracted_results": vuln.extracted_results,
            "curl_command": vuln.curl_command,
            "timestamp": vuln.timestamp.isoformat()
        })

    return result_list


@router.get("/{scan_id}/nse-findings", summary="Get NSE script findings")
async def get_scan_nse_findings(
    scan_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity: critical,high,medium,low,info (comma-separated)"),
    script_id: Optional[str] = Query(None, description="Filter by script ID (e.g., rdp-enum-encryption)"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all NSE script findings for a scan, sorted by severity."""
    # Verify scan access
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Build query
    query = (
        select(NseFinding)
        .join(Port, NseFinding.port_id == Port.id)
        .join(ScanTarget, Port.scan_target_id == ScanTarget.id)
        .where(ScanTarget.scan_id == scan_id)
    )

    # Filter by severity if provided
    if severity:
        severities = [s.strip() for s in severity.split(',')]
        query = query.where(NseFinding.severity.in_(severities))

    # Filter by script_id if provided
    if script_id:
        query = query.where(NseFinding.script_id == script_id)

    findings_result = await db.execute(query)
    findings = findings_result.scalars().all()

    # Sort by severity
    severity_order = {
        'critical': 1,
        'high': 2,
        'medium': 3,
        'low': 4,
        'info': 5
    }
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 99))

    # Join with port and target info
    result_list = []
    for finding in sorted_findings:
        port_result = await db.execute(
            select(Port).where(Port.id == finding.port_id)
        )
        port = port_result.scalar_one()

        target_result = await db.execute(
            select(ScanTarget).where(ScanTarget.id == port.scan_target_id)
        )
        target = target_result.scalar_one()

        result_list.append({
            "id": str(finding.id),
            "ip_address": target.ip_address,
            "device_name": target.device_name,
            "port": port.port,
            "protocol": port.protocol,
            "service_name": port.service_name,
            "script_id": finding.script_id,
            "profile_name": finding.profile_name,
            "raw_output": finding.raw_output,
            "elements": finding.elements,
            "severity": finding.severity,
            "error": finding.error
        })

    return result_list


@router.get("/{scan_id}/sslscan-results", summary="Get SSL/TLS scan results")
async def get_scan_sslscan_results(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all SSL/TLS scan results for a scan, including protocol support, ciphers, and certificate info."""
    # Verify scan access
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Get all sslscan results for this scan
    query = (
        select(SslScanResult)
        .join(Port, SslScanResult.port_id == Port.id)
        .join(ScanTarget, Port.scan_target_id == ScanTarget.id)
        .where(ScanTarget.scan_id == scan_id)
    )

    results = await db.execute(query)
    ssl_results = results.scalars().all()

    # Join with port and target info
    result_list = []
    for ssl_result in ssl_results:
        port_result = await db.execute(
            select(Port).where(Port.id == ssl_result.port_id)
        )
        port = port_result.scalar_one()

        target_result = await db.execute(
            select(ScanTarget).where(ScanTarget.id == port.scan_target_id)
        )
        target = target_result.scalar_one()

        result_list.append({
            "id": str(ssl_result.id),
            "ip_address": target.ip_address,
            "device_name": target.device_name,
            "port": port.port,
            "protocol": port.protocol,
            "service_name": port.service_name,
            # Protocol support
            "sslv2_enabled": ssl_result.sslv2_enabled,
            "sslv3_enabled": ssl_result.sslv3_enabled,
            "tlsv10_enabled": ssl_result.tlsv10_enabled,
            "tlsv11_enabled": ssl_result.tlsv11_enabled,
            "tlsv12_enabled": ssl_result.tlsv12_enabled,
            "tlsv13_enabled": ssl_result.tlsv13_enabled,
            # Security features
            "fallback_scsv_supported": ssl_result.fallback_scsv_supported,
            "secure_renegotiation": ssl_result.secure_renegotiation,
            "compression_supported": ssl_result.compression_supported,
            "heartbleed_vulnerable": ssl_result.heartbleed_vulnerable,
            # Ciphers and key exchange
            "ciphers": ssl_result.ciphers,
            "key_exchange_groups": ssl_result.key_exchange_groups,
            # Certificate info
            "cert_subject": ssl_result.cert_subject,
            "cert_issuer": ssl_result.cert_issuer,
            "cert_altnames": ssl_result.cert_altnames,
            "cert_not_before": ssl_result.cert_not_before,
            "cert_not_after": ssl_result.cert_not_after,
            "cert_expired": ssl_result.cert_expired,
            "cert_self_signed": ssl_result.cert_self_signed,
            "cert_signature_algorithm": ssl_result.cert_signature_algorithm,
            "cert_key_type": ssl_result.cert_key_type,
            "cert_key_bits": ssl_result.cert_key_bits,
            # Analysis results
            "findings": ssl_result.findings,
            "grade": ssl_result.grade,
            # Status
            "connection_failed": ssl_result.connection_failed,
            "failure_reason": ssl_result.failure_reason
        })

    return result_list


@router.get("/{scan_id}/httpx-results", summary="Get HTTP probe results")
async def get_scan_httpx_results(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get all httpx HTTP probe results for a scan.

    Returns HTTP metadata including status codes, titles, technology detection,
    CDN/WAF detection, and TLS information for each probed HTTP port.
    """
    # Verify scan access
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Get all httpx results for this scan
    query = (
        select(HttpxResult)
        .join(Port, HttpxResult.port_id == Port.id)
        .join(ScanTarget, Port.scan_target_id == ScanTarget.id)
        .where(ScanTarget.scan_id == scan_id)
    )

    results = await db.execute(query)
    httpx_results = results.scalars().all()

    # Join with port and target info
    result_list = []
    for httpx_result in httpx_results:
        port_result = await db.execute(
            select(Port).where(Port.id == httpx_result.port_id)
        )
        port = port_result.scalar_one()

        target_result = await db.execute(
            select(ScanTarget).where(ScanTarget.id == port.scan_target_id)
        )
        target = target_result.scalar_one()

        result_list.append({
            "id": str(httpx_result.id),
            "port_id": str(httpx_result.port_id),
            "ip_address": target.ip_address,
            "port": port.port,
            # HTTP Response
            "status_code": httpx_result.status_code,
            "content_length": httpx_result.content_length,
            "content_type": httpx_result.content_type,
            "title": httpx_result.title,
            "webserver": httpx_result.webserver,
            # Technology detection
            "technologies": httpx_result.technologies or [],
            # Infrastructure
            "cdn": httpx_result.cdn,
            "waf": httpx_result.waf,
            "final_url": httpx_result.final_url,
            "redirect_chain": httpx_result.redirect_chain or [],
            # Metadata
            "response_time_ms": httpx_result.response_time_ms,
            # TLS info
            "tls_version": httpx_result.tls_version,
            "jarm_hash": httpx_result.jarm_hash,
            # Connection status
            "connection_failed": httpx_result.connection_failed,
            "failure_reason": httpx_result.failure_reason
        })

    return result_list
