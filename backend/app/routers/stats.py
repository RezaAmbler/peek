from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case
from ..database import get_db
from ..models import Scan, ScanConfig, Vulnerability, User, ScanStatus, ScheduledScan, ScanTarget, Port
from ..routers.auth import get_current_user
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from ..core.timeutil import utcnow

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


class TopVulnerableHost(BaseModel):
    ip_address: str
    device_name: Optional[str]
    vulnerability_count: int
    critical_count: int


class ServiceCount(BaseModel):
    service_name: str
    count: int


class DailyScanCount(BaseModel):
    date: str
    count: int


class DashboardStats(BaseModel):
    total_scans: int
    scans_by_status: List[ScanStatusCount]
    # Finding/port/host/service figures describe the current state: they count
    # only the latest completed run of each scan config, so re-running the same
    # targets does not inflate them. total_findings_all_runs is the old sum.
    findings_scope: str = "latest_completed_run_per_config"
    scans_counted: int = 0
    total_findings: int = 0  # every severity, info included
    total_vulnerabilities: int  # findings with a severity above info
    total_findings_all_runs: int = 0
    vulnerabilities_by_severity: List[VulnerabilitySeverityCount]
    total_configs: int
    recent_scans: List[RecentScan]
    # New fields
    total_ports: int
    active_schedules: int
    next_scheduled_run: Optional[datetime]
    top_vulnerable_hosts: List[TopVulnerableHost]
    services_breakdown: List[ServiceCount]
    scans_by_day: List[DailyScanCount]


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

    # Every scan of this user (only used for the all-runs total)
    all_scan_ids_result = await db.execute(
        select(Scan.id).where(Scan.user_id == current_user.id)
    )
    all_scan_ids = [str(row[0]) for row in all_scan_ids_result]

    # Latest completed run of each config: the scans that describe "now".
    # Re-runs of the same targets would otherwise be summed up again and again.
    completed_result = await db.execute(
        select(Scan.id, Scan.config_id, Scan.total_open_ports)
        .where(Scan.user_id == current_user.id)
        .where(Scan.status == ScanStatus.COMPLETED.value)
        .order_by(Scan.created_at.desc(), Scan.run_number.desc())
    )
    latest_by_config = {}
    for scan_id, config_id, open_ports in completed_result:
        latest_by_config.setdefault(str(config_id), (str(scan_id), open_ports or 0))
    scan_ids = [scan_id for scan_id, _ in latest_by_config.values()]

    total_findings = 0
    total_findings_all_runs = 0
    vulns_by_severity = []

    if all_scan_ids:
        all_runs_result = await db.execute(
            select(func.count(Vulnerability.id))
            .join(ScanTarget, Vulnerability.scan_target_id == ScanTarget.id)
            .where(ScanTarget.scan_id.in_(all_scan_ids))
        )
        total_findings_all_runs = all_runs_result.scalar() or 0

    if scan_ids:
        # Findings by severity (join through ScanTarget)
        severity_result = await db.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .join(ScanTarget, Vulnerability.scan_target_id == ScanTarget.id)
            .where(ScanTarget.scan_id.in_(scan_ids))
            .group_by(Vulnerability.severity)
        )
        vulns_by_severity = [
            VulnerabilitySeverityCount(severity=row[0] or 'unknown', count=row[1])
            for row in severity_result
        ]
        total_findings = sum(item.count for item in vulns_by_severity)

    total_vulns = sum(
        item.count for item in vulns_by_severity if item.severity.lower() != 'info'
    )

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

    # Open ports of the latest completed run of each config
    total_ports = sum(open_ports for _, open_ports in latest_by_config.values())

    # Active scheduled scans count
    active_schedules_result = await db.execute(
        select(func.count(ScheduledScan.id))
        .where(ScheduledScan.user_id == current_user.id)
        .where(ScheduledScan.is_active == True)
    )
    active_schedules = active_schedules_result.scalar() or 0

    # Next scheduled run
    next_run_result = await db.execute(
        select(func.min(ScheduledScan.next_run_at))
        .where(ScheduledScan.user_id == current_user.id)
        .where(ScheduledScan.is_active == True)
        .where(ScheduledScan.next_run_at.isnot(None))
    )
    next_scheduled_run = next_run_result.scalar()

    # Top vulnerable hosts
    top_vulnerable_hosts = []
    if scan_ids:
        top_hosts_result = await db.execute(
            select(
                ScanTarget.ip_address,
                ScanTarget.device_name,
                func.count(Vulnerability.id).label('vuln_count'),
                func.sum(case((Vulnerability.severity == 'critical', 1), else_=0)).label('critical_count')
            )
            .join(Vulnerability, Vulnerability.scan_target_id == ScanTarget.id)
            .where(ScanTarget.scan_id.in_(scan_ids))
            .group_by(ScanTarget.ip_address, ScanTarget.device_name)
            .order_by(func.count(Vulnerability.id).desc())
            .limit(5)
        )
        top_vulnerable_hosts = [
            TopVulnerableHost(
                ip_address=row[0],
                device_name=row[1],
                vulnerability_count=row[2],
                critical_count=row[3] or 0
            )
            for row in top_hosts_result
        ]

    # Services breakdown
    services_breakdown = []
    if scan_ids:
        services_result = await db.execute(
            select(Port.service_name, func.count(Port.id))
            .join(ScanTarget, Port.scan_target_id == ScanTarget.id)
            .where(ScanTarget.scan_id.in_(scan_ids))
            .where(Port.service_name.isnot(None))
            .where(Port.service_name != '')
            .group_by(Port.service_name)
            .order_by(func.count(Port.id).desc())
            .limit(10)
        )
        services_breakdown = [
            ServiceCount(service_name=row[0], count=row[1])
            for row in services_result
        ]

    # Scans by day (last 7 days)
    seven_days_ago = utcnow() - timedelta(days=7)
    daily_counts_result = await db.execute(
        select(
            func.date(Scan.created_at).label('scan_date'),
            func.count(Scan.id)
        )
        .where(Scan.user_id == current_user.id)
        .where(Scan.created_at >= seven_days_ago)
        .group_by(func.date(Scan.created_at))
        .order_by(func.date(Scan.created_at))
    )
    scans_by_day = [
        DailyScanCount(date=str(row[0]), count=row[1])
        for row in daily_counts_result
    ]

    return DashboardStats(
        total_scans=total_scans,
        scans_by_status=scans_by_status,
        scans_counted=len(scan_ids),
        total_findings=total_findings,
        total_vulnerabilities=total_vulns,
        total_findings_all_runs=total_findings_all_runs,
        vulnerabilities_by_severity=vulns_by_severity,
        total_configs=total_configs,
        recent_scans=recent_scans,
        total_ports=total_ports,
        active_schedules=active_schedules,
        next_scheduled_run=next_scheduled_run,
        top_vulnerable_hosts=top_vulnerable_hosts,
        services_breakdown=services_breakdown,
        scans_by_day=scans_by_day,
    )
