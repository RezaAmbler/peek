from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, delete
from typing import Optional
import csv
import io
import uuid
from ..database import get_db
from ..models import Scan, ScanTarget, ScanConfig, User, ScanStatus, Port, SSHAudit, Vulnerability
from ..schemas.scan import (
    ScanCreate,
    ScanCreateFromCSV,
    ScanUpdate,
    ScanResponse,
    ScanDetailResponse,
    ScanListResponse,
    TargetInput
)
from ..routers.auth import get_current_user

router = APIRouter()

def parse_csv_targets(csv_content: str) -> list[TargetInput]:
    """Parse CSV content into target list"""
    targets = []
    reader = csv.DictReader(io.StringIO(csv_content))

    for row in reader:
        # Support both "ip" and "ip_address" column names
        ip = row.get('ip_address') or row.get('ip') or row.get('IP')
        device = row.get('device_name') or row.get('device') or row.get('name') or row.get('hostname')

        if not ip:
            continue

        targets.append(TargetInput(ip_address=ip.strip(), device_name=device.strip() if device else None))

    return targets

@router.get("", response_model=ScanListResponse)
async def list_scans(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List scans for the current user"""
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

    return ScanListResponse(
        scans=scans,
        total=total,
        page=page,
        pages=(total + limit - 1) // limit
    )

@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get scan details including targets"""
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

@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new scan with targets"""
    # Verify config exists and user has access
    # Convert UUID to string for SQLite string column comparison
    config_id_str = str(scan_data.config_id)
    config_result = await db.execute(
        select(ScanConfig).where(ScanConfig.id == config_id_str)
    )
    config = config_result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")

    if config.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to use this configuration")

    # Create scan
    scan = Scan(
        user_id=current_user.id,
        created_by_id=current_user.id,
        organization_id=None,  # Phase 1-4: always NULL
        config_id=config_id_str,
        name=scan_data.name,
        description=scan_data.description,
        baseline_scan_id=str(scan_data.baseline_scan_id) if scan_data.baseline_scan_id else None,
        total_targets=len(scan_data.targets)
    )
    db.add(scan)
    await db.flush()  # Get scan.id

    # Create targets
    for idx, target in enumerate(scan_data.targets):
        scan_target = ScanTarget(
            scan_id=scan.id,
            ip_address=target.ip_address,
            device_name=target.device_name,
            sequence=idx
        )
        db.add(scan_target)

    await db.commit()
    await db.refresh(scan)

    return scan

@router.post("/from-csv", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan_from_csv(
    scan_data: ScanCreateFromCSV,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new scan with targets from CSV"""
    # Parse CSV
    try:
        targets = parse_csv_targets(scan_data.targets_csv)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid CSV format: {str(e)}")

    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets found in CSV")

    # Create using regular create logic
    create_data = ScanCreate(
        name=scan_data.name,
        description=scan_data.description,
        config_id=scan_data.config_id,
        targets=targets,
        baseline_scan_id=scan_data.baseline_scan_id
    )

    return await create_scan(create_data, current_user, db)

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
    """Update a scan (only if status is pending)"""
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

    # Validate config exists if provided (before updating fields)
    if scan_update.config_id:
        config_id_str = str(scan_update.config_id)
        config_result = await db.execute(
            select(ScanConfig).where(ScanConfig.id == config_id_str)
        )
        config = config_result.scalar_one_or_none()
        if not config:
            raise HTTPException(status_code=404, detail="Configuration not found")
        if config.user_id != current_user.id and not current_user.is_admin:
            raise HTTPException(status_code=403, detail="Not authorized to use this configuration")

    # Update basic fields - convert UUIDs to strings for SQLite
    update_data = scan_update.model_dump(exclude_unset=True, exclude={'targets'})
    for field, value in update_data.items():
        # Convert UUID fields to strings
        if field in ('config_id', 'baseline_scan_id') and value is not None:
            value = str(value)
        setattr(scan, field, value)

    # Update targets if provided
    if scan_update.targets is not None:
        # Delete existing targets
        await db.execute(
            delete(ScanTarget).where(ScanTarget.scan_id == scan_id)
        )
        await db.flush()

        # Add new targets
        for idx, target in enumerate(scan_update.targets):
            scan_target = ScanTarget(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                ip_address=target.ip_address,
                device_name=target.device_name,
                sequence=idx
            )
            db.add(scan_target)

        # Update total_targets count
        scan.total_targets = len(scan_update.targets)

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

@router.post("/{scan_id}/start", response_model=ScanResponse)
async def start_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Start a pending scan (queues it for execution)"""
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
    Restart a failed/completed/cancelled scan by creating a new scan with the same configuration.

    Creates a new scan with:
    - Same name (with " (retry)" suffix)
    - Same description
    - Same configuration
    - Same targets
    - Automatically starts the new scan

    Returns the new scan object.
    """
    # Get original scan
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

    # Get original targets
    targets_result = await db.execute(
        select(ScanTarget)
        .where(ScanTarget.scan_id == scan_id)
        .order_by(ScanTarget.sequence)
    )
    original_targets = targets_result.scalars().all()

    if not original_targets:
        raise HTTPException(status_code=400, detail="Original scan has no targets")

    # Create new scan name
    new_name = original_scan.name
    if not new_name.endswith(" (retry)"):
        new_name = f"{new_name} (retry)"

    # Create new scan
    new_scan = Scan(
        user_id=current_user.id,
        created_by_id=current_user.id,
        organization_id=original_scan.organization_id,
        config_id=original_scan.config_id,
        name=new_name,
        description=original_scan.description,
        baseline_scan_id=original_scan.baseline_scan_id,
        total_targets=len(original_targets)
    )
    db.add(new_scan)
    await db.flush()  # Get new_scan.id

    # Copy targets to new scan
    for idx, target in enumerate(original_targets):
        new_target = ScanTarget(
            scan_id=new_scan.id,
            ip_address=target.ip_address,
            device_name=target.device_name,
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

@router.get("/{scan_id}/ports")
async def get_scan_ports(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all ports discovered in a scan"""
    # Verify scan access
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Get all ports for this scan
    ports_query = select(Port).join(ScanTarget).where(
        ScanTarget.scan_id == scan_id
    ).order_by(ScanTarget.ip_address, Port.port)

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

@router.get("/{scan_id}/vulnerabilities")
async def get_scan_vulnerabilities(
    scan_id: str,
    severity: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all vulnerabilities found in a scan"""
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
            "description": vuln.description,
            "reference": vuln.reference,
            "tags": vuln.tags,
            "extracted_results": vuln.extracted_results,
            "curl_command": vuln.curl_command,
            "timestamp": vuln.timestamp.isoformat()
        })

    return result_list
