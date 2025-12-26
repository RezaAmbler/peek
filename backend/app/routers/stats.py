from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case
from ..database import get_db
from ..models import Scan, ScanConfig, Vulnerability, User, ScanStatus
from ..routers.auth import get_current_user
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

router = APIRouter()


class ScanStatusCount(BaseModel):
    status: str
    count: int


class VulnerabilitySeverityCount(BaseModel):
    severity: str
    count: int


class RecentScan(BaseModel):
    id: str
    config_name: Optional[str]
    run_number: int
    status: str
    created_at: datetime
    total_open_ports: int
    total_vulnerabilities: int


class DashboardStats(BaseModel):
    total_scans: int
    scans_by_status: List[ScanStatusCount]
    total_vulnerabilities: int
    vulnerabilities_by_severity: List[VulnerabilitySeverityCount]
    total_configs: int
    recent_scans: List[RecentScan]


@router.get("", response_model=DashboardStats, summary="Get dashboard statistics")
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get aggregated statistics for the dashboard."""

    # Total scans count
    total_scans_result = await db.execute(
        select(func.count(Scan.id)).where(Scan.user_id == current_user.id)
    )
    total_scans = total_scans_result.scalar() or 0

    # Scans by status
    status_result = await db.execute(
        select(Scan.status, func.count(Scan.id))
        .where(Scan.user_id == current_user.id)
        .group_by(Scan.status)
    )
    scans_by_status = [
        ScanStatusCount(status=row[0], count=row[1])
        for row in status_result
    ]

    # Get all scan IDs for this user to filter vulnerabilities
    scan_ids_result = await db.execute(
        select(Scan.id).where(Scan.user_id == current_user.id)
    )
    scan_ids = [str(row[0]) for row in scan_ids_result]

    # Total vulnerabilities across all user's scans
    total_vulns = 0
    vulns_by_severity = []

    if scan_ids:
        total_vulns_result = await db.execute(
            select(func.count(Vulnerability.id))
            .where(Vulnerability.scan_id.in_(scan_ids))
        )
        total_vulns = total_vulns_result.scalar() or 0

        # Vulnerabilities by severity
        severity_result = await db.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.scan_id.in_(scan_ids))
            .group_by(Vulnerability.severity)
        )
        vulns_by_severity = [
            VulnerabilitySeverityCount(severity=row[0] or 'unknown', count=row[1])
            for row in severity_result
        ]

    # Total configs
    configs_result = await db.execute(
        select(func.count(ScanConfig.id)).where(ScanConfig.user_id == current_user.id)
    )
    total_configs = configs_result.scalar() or 0

    # Recent scans (last 5)
    recent_result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(5)
    )
    recent_scans_raw = recent_result.scalars().all()

    # Fetch config names
    config_ids = list(set(s.config_id for s in recent_scans_raw if s.config_id))
    config_names = {}
    if config_ids:
        configs_result = await db.execute(
            select(ScanConfig.id, ScanConfig.name).where(ScanConfig.id.in_(config_ids))
        )
        config_names = {str(row[0]): row[1] for row in configs_result}

    recent_scans = [
        RecentScan(
            id=str(scan.id),
            config_name=config_names.get(str(scan.config_id)),
            run_number=scan.run_number,
            status=scan.status,
            created_at=scan.created_at,
            total_open_ports=scan.total_open_ports or 0,
            total_vulnerabilities=scan.total_vulnerabilities or 0,
        )
        for scan in recent_scans_raw
    ]

    return DashboardStats(
        total_scans=total_scans,
        scans_by_status=scans_by_status,
        total_vulnerabilities=total_vulns,
        vulnerabilities_by_severity=vulns_by_severity,
        total_configs=total_configs,
        recent_scans=recent_scans,
    )
