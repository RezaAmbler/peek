from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from typing import Dict, Any
from ..database import get_db, SyncSessionLocal
from ..models import Scan, ScanComparison, User
from ..routers.auth import get_current_user
from ..services.comparison_service import ComparisonService

router = APIRouter()

# Fields returned to clients for a comparison (matches the GET endpoints below).
_COMPARISON_FIELDS = (
    "id", "baseline_scan_id", "current_scan_id", "total_changes", "new_ports",
    "closed_ports", "version_changes", "new_vulnerabilities", "fixed_vulnerabilities",
    "critical_changes", "high_changes", "medium_changes", "positive_changes",
    "summary", "changes",
)


def _run_comparison(baseline_scan_id: str, current_scan_id: str, user_id: str) -> Dict[str, Any]:
    """Run + persist a comparison via ComparisonService on a sync session.

    Executed in a threadpool from the async endpoint. ComparisonService is the
    single source of truth for the diff (fingerprint keying, ephemeral-port
    collapsing, triage suppression, version + SSH-audit changes) and is heavily
    unit tested against a sync Session. We extract a plain dict before the session
    closes so the async caller can serialize it.
    """
    session = SyncSessionLocal()
    try:
        c = ComparisonService(session).compare_scans(baseline_scan_id, current_scan_id, user_id)
        result: Dict[str, Any] = {field: getattr(c, field) for field in _COMPARISON_FIELDS}
        result["created_at"] = c.created_at.isoformat() if c.created_at else None
        return result
    finally:
        session.close()


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

    # Auto-swap so baseline is always chronologically earlier.
    # The "what changed since baseline" semantic requires baseline to be the earlier scan.
    baseline_time = baseline.finished_at or baseline.started_at or baseline.created_at
    current_time = current.finished_at or current.started_at or current.created_at
    if baseline_time and current_time and baseline_time > current_time:
        baseline, current = current, baseline
        baseline_scan_id, current_scan_id = current_scan_id, baseline_scan_id

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

    # Both scans must be from the same configuration
    if baseline.config_id != current.config_id:
        raise HTTPException(
            status_code=400,
            detail="Cannot compare scans from different configurations. Both scans must use the same config to ensure meaningful comparison."
        )

    # Same config_id is necessary but not sufficient: the config may have been
    # edited between runs. config_hash equality is what guarantees the two
    # scans actually ran with the same comparable settings.
    if baseline.config_hash and current.config_hash and baseline.config_hash != current.config_hash:
        raise HTTPException(
            status_code=400,
            detail="Configuration has changed since the baseline scan; not directly comparable. "
                   "Run this configuration again to produce a comparable scan."
        )

    # Delegate the diff + persistence to ComparisonService (single source of
    # truth: fingerprint keying, ephemeral-port collapsing, triage suppression,
    # version + SSH-audit changes). It uses the sync ORM, so run it in a
    # threadpool with a sync session. The router keeps the async access checks
    # above (auth, completed, config-hash) which the service does not do.
    return await run_in_threadpool(
        _run_comparison, baseline_scan_id, current_scan_id, str(current_user.id)
    )

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
