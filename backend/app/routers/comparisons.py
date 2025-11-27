from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, text
from typing import Optional, List, Dict, Any
from ..database import get_db
from ..models import Scan, ScanComparison, User
from ..routers.auth import get_current_user
import uuid
from datetime import datetime

router = APIRouter()


async def _get_ports_by_scan(db: AsyncSession, scan_id: str) -> List[Dict[str, Any]]:
    """Get all open ports for a scan"""
    query = text("""
        SELECT st.ip_address, st.device_name, p.port, p.protocol, p.state, p.service_name, p.version
        FROM ports p
        JOIN scan_targets st ON p.scan_target_id = st.id
        WHERE st.scan_id = :scan_id AND p.state = 'open'
    """)
    result = await db.execute(query, {'scan_id': scan_id})
    return [
        {'ip_address': r[0], 'device_name': r[1], 'port': r[2], 'protocol': r[3],
         'state': r[4], 'service_name': r[5], 'version': r[6]}
        for r in result
    ]


async def _get_vulnerabilities_by_scan(db: AsyncSession, scan_id: str) -> List[Dict[str, Any]]:
    """Get all vulnerabilities for a scan"""
    query = text("""
        SELECT st.ip_address, st.device_name, v.template_id, v.name, v.severity, v.port, v.matched_at
        FROM vulnerabilities v
        JOIN scan_targets st ON v.scan_target_id = st.id
        WHERE st.scan_id = :scan_id
    """)
    result = await db.execute(query, {'scan_id': scan_id})
    return [
        {'ip_address': r[0], 'device_name': r[1], 'template_id': r[2], 'name': r[3],
         'severity': r[4], 'port': r[5], 'matched_at': r[6]}
        for r in result
    ]


@router.post("/compare")
async def create_comparison(
    baseline_scan_id: str,
    current_scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Compare two scans and generate a comparison report.
    """
    # Verify both scans exist and user has access
    baseline_result = await db.execute(select(Scan).where(Scan.id == baseline_scan_id))
    baseline = baseline_result.scalar_one_or_none()

    current_result = await db.execute(select(Scan).where(Scan.id == current_scan_id))
    current = current_result.scalar_one_or_none()

    if not baseline or not current:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    # Check authorization
    if baseline.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to access baseline scan")

    if current.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to access current scan")

    # Both scans must be completed
    if baseline.status != "completed":
        raise HTTPException(status_code=400, detail="Baseline scan is not completed")

    if current.status != "completed":
        raise HTTPException(status_code=400, detail="Current scan is not completed")

    # Get ports from both scans
    baseline_ports = await _get_ports_by_scan(db, baseline_scan_id)
    current_ports = await _get_ports_by_scan(db, current_scan_id)

    # Get vulnerabilities from both scans
    baseline_vulns = await _get_vulnerabilities_by_scan(db, baseline_scan_id)
    current_vulns = await _get_vulnerabilities_by_scan(db, current_scan_id)

    # Compare ports
    changes = []
    baseline_port_keys = {f"{p['ip_address']}:{p['port']}:{p['protocol']}": p for p in baseline_ports}
    current_port_keys = {f"{p['ip_address']}:{p['port']}:{p['protocol']}": p for p in current_ports}

    # New ports
    for key, port in current_port_keys.items():
        if key not in baseline_port_keys:
            changes.append({
                'type': 'NEW_PORT', 'severity': 'HIGH', 'category': 'port',
                'ip_address': port['ip_address'], 'device_name': port['device_name'],
                'port': port['port'], 'protocol': port['protocol'],
                'service_name': port['service_name'], 'version': port['version'],
                'description': f"New open port: {port['port']}/{port['protocol']}"
            })

    # Closed ports
    for key, port in baseline_port_keys.items():
        if key not in current_port_keys:
            changes.append({
                'type': 'CLOSED_PORT', 'severity': 'POSITIVE', 'category': 'port',
                'ip_address': port['ip_address'], 'device_name': port['device_name'],
                'port': port['port'], 'protocol': port['protocol'],
                'service_name': port['service_name'],
                'description': f"Port closed: {port['port']}/{port['protocol']}"
            })

    # Compare vulnerabilities
    baseline_vuln_keys = {f"{v['ip_address']}:{v['template_id']}:{v['port']}": v for v in baseline_vulns}
    current_vuln_keys = {f"{v['ip_address']}:{v['template_id']}:{v['port']}": v for v in current_vulns}

    # New vulnerabilities
    for key, vuln in current_vuln_keys.items():
        if key not in baseline_vuln_keys:
            sev_map = {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM', 'low': 'LOW', 'info': 'INFO'}
            changes.append({
                'type': 'NEW_VULNERABILITY', 'severity': sev_map.get(vuln['severity'], 'MEDIUM'),
                'category': 'vulnerability', 'ip_address': vuln['ip_address'],
                'device_name': vuln['device_name'], 'port': vuln['port'],
                'template_id': vuln['template_id'], 'name': vuln['name'],
                'vuln_severity': vuln['severity'],
                'description': f"New {vuln['severity']} vulnerability: {vuln['name']}"
            })

    # Fixed vulnerabilities
    for key, vuln in baseline_vuln_keys.items():
        if key not in current_vuln_keys:
            changes.append({
                'type': 'FIXED_VULNERABILITY', 'severity': 'POSITIVE', 'category': 'vulnerability',
                'ip_address': vuln['ip_address'], 'device_name': vuln['device_name'],
                'port': vuln['port'], 'template_id': vuln['template_id'], 'name': vuln['name'],
                'vuln_severity': vuln['severity'],
                'description': f"Fixed {vuln['severity']} vulnerability: {vuln['name']}"
            })

    # Calculate statistics
    new_ports = sum(1 for c in changes if c['type'] == 'NEW_PORT')
    closed_ports = sum(1 for c in changes if c['type'] == 'CLOSED_PORT')
    new_vulns = sum(1 for c in changes if c['type'] == 'NEW_VULNERABILITY')
    fixed_vulns = sum(1 for c in changes if c['type'] == 'FIXED_VULNERABILITY')
    critical = sum(1 for c in changes if c['severity'] == 'CRITICAL')
    high = sum(1 for c in changes if c['severity'] == 'HIGH')
    medium = sum(1 for c in changes if c['severity'] == 'MEDIUM')
    positive = sum(1 for c in changes if c['severity'] == 'POSITIVE')

    # Generate summary
    summary_lines = [
        f"Comparison: {baseline.name} → {current.name}",
        f"Baseline: {baseline.created_at.strftime('%Y-%m-%d %H:%M')}",
        f"Current: {current.created_at.strftime('%Y-%m-%d %H:%M')}",
        "",
    ]
    if len(changes) == 0:
        summary_lines.append("✅ No changes detected")
    else:
        summary_lines.append(f"📊 Total Changes: {len(changes)}")
        if new_ports: summary_lines.append(f"🔴 New Ports: {new_ports}")
        if closed_ports: summary_lines.append(f"🟢 Closed Ports: {closed_ports}")
        if new_vulns: summary_lines.append(f"🔴 New Vulnerabilities: {new_vulns}")
        if fixed_vulns: summary_lines.append(f"🟢 Fixed Vulnerabilities: {fixed_vulns}")

    # Create comparison record
    comparison = ScanComparison(
        id=str(uuid.uuid4()),
        baseline_scan_id=baseline_scan_id,
        current_scan_id=current_scan_id,
        created_by_id=str(current_user.id),
        changes=changes,
        total_changes=len(changes),
        new_ports=new_ports,
        closed_ports=closed_ports,
        version_changes=0,
        new_vulnerabilities=new_vulns,
        fixed_vulnerabilities=fixed_vulns,
        critical_changes=critical,
        high_changes=high,
        medium_changes=medium,
        low_changes=0,
        positive_changes=positive,
        summary="\n".join(summary_lines)
    )
    db.add(comparison)
    await db.commit()
    await db.refresh(comparison)

    # Return comparison result
    return {
        "id": comparison.id,
        "baseline_scan_id": comparison.baseline_scan_id,
        "current_scan_id": comparison.current_scan_id,
        "created_at": comparison.created_at.isoformat(),
        "total_changes": comparison.total_changes,
        "new_ports": comparison.new_ports,
        "closed_ports": comparison.closed_ports,
        "version_changes": comparison.version_changes,
        "new_vulnerabilities": comparison.new_vulnerabilities,
        "fixed_vulnerabilities": comparison.fixed_vulnerabilities,
        "critical_changes": comparison.critical_changes,
        "high_changes": comparison.high_changes,
        "medium_changes": comparison.medium_changes,
        "positive_changes": comparison.positive_changes,
        "summary": comparison.summary,
        "changes": comparison.changes
    }

@router.get("/{comparison_id}")
async def get_comparison(
    comparison_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get a comparison by ID"""
    result = await db.execute(
        select(ScanComparison).where(ScanComparison.id == comparison_id)
    )
    comparison = result.scalar_one_or_none()

    if not comparison:
        raise HTTPException(status_code=404, detail="Comparison not found")

    # Check authorization (must own one of the scans being compared)
    baseline_result = await db.execute(select(Scan).where(Scan.id == comparison.baseline_scan_id))
    baseline = baseline_result.scalar_one()

    if baseline.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    return {
        "id": comparison.id,
        "baseline_scan_id": comparison.baseline_scan_id,
        "current_scan_id": comparison.current_scan_id,
        "created_at": comparison.created_at.isoformat(),
        "total_changes": comparison.total_changes,
        "new_ports": comparison.new_ports,
        "closed_ports": comparison.closed_ports,
        "version_changes": comparison.version_changes,
        "new_vulnerabilities": comparison.new_vulnerabilities,
        "fixed_vulnerabilities": comparison.fixed_vulnerabilities,
        "critical_changes": comparison.critical_changes,
        "high_changes": comparison.high_changes,
        "medium_changes": comparison.medium_changes,
        "positive_changes": comparison.positive_changes,
        "summary": comparison.summary,
        "changes": comparison.changes
    }

@router.get("/scan/{scan_id}")
async def list_comparisons_for_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List all comparisons involving a specific scan"""
    # Verify scan access
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Get all comparisons where this scan is either baseline or current
    comparisons_result = await db.execute(
        select(ScanComparison).where(
            or_(
                ScanComparison.baseline_scan_id == scan_id,
                ScanComparison.current_scan_id == scan_id
            )
        ).order_by(ScanComparison.created_at.desc())
    )
    comparisons = comparisons_result.scalars().all()

    return [
        {
            "id": comp.id,
            "baseline_scan_id": comp.baseline_scan_id,
            "current_scan_id": comp.current_scan_id,
            "created_at": comp.created_at.isoformat(),
            "total_changes": comp.total_changes,
            "summary": comp.summary
        }
        for comp in comparisons
    ]
