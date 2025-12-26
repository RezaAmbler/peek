import re
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..database import get_db
from ..models import Scan, User
from ..routers.auth import get_current_user
from ..services.report_service import ReportService
from ..db.sync_session import get_sync_db

router = APIRouter()

def sanitize_filename(name: str) -> str:
    """Sanitize filename for use in HTTP headers (ASCII only)."""
    # Replace common unicode dashes with ASCII hyphen
    name = name.replace('\u2014', '-').replace('\u2013', '-')
    # Remove any remaining non-ASCII characters
    name = name.encode('ascii', 'ignore').decode('ascii')
    # Replace spaces and special chars with underscores
    name = re.sub(r'[^\w\-.]', '_', name)
    # Collapse multiple underscores
    name = re.sub(r'_+', '_', name)
    return name.strip('_') or 'report'

@router.get("/{scan_id}/pdf/executive", summary="Executive summary PDF")
async def get_executive_summary_pdf(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate a high-level executive summary PDF suitable for management reporting."""
    # Verify scan access
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Generate report using sync session
    with get_sync_db() as sync_db:
        service = ReportService(sync_db)
        buffer = service.generate_executive_summary_pdf(scan_id)

    filename = f"executive_summary_{sanitize_filename(scan.name)}.pdf"

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/{scan_id}/pdf/technical", summary="Technical report PDF")
async def get_technical_report_pdf(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate a detailed technical PDF with all ports, services, and vulnerabilities."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    with get_sync_db() as sync_db:
        service = ReportService(sync_db)
        buffer = service.generate_technical_report_pdf(scan_id)

    filename = f"technical_report_{sanitize_filename(scan.name)}.pdf"

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/comparison/{comparison_id}/pdf")
async def get_comparison_report_pdf(
    comparison_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate comparison report PDF"""
    from ..models import ScanComparison

    result = await db.execute(select(ScanComparison).where(ScanComparison.id == comparison_id))
    comparison = result.scalar_one_or_none()

    if not comparison:
        raise HTTPException(status_code=404, detail="Comparison not found")

    # Verify access to baseline scan
    baseline_result = await db.execute(select(Scan).where(Scan.id == comparison.baseline_scan_id))
    baseline = baseline_result.scalar_one()

    if baseline.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    with get_sync_db() as sync_db:
        service = ReportService(sync_db)
        buffer = service.generate_comparison_report_pdf(comparison_id)

    filename = f"comparison_report_{comparison_id[:8]}.pdf"

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/{scan_id}/html")
async def get_html_report(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate HTML report"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    with get_sync_db() as sync_db:
        service = ReportService(sync_db)
        html = service.generate_html_report(scan_id)

    return StreamingResponse(
        iter([html]),
        media_type="text/html"
    )

@router.get("/{scan_id}/csv/vulnerabilities", summary="Export vulnerabilities CSV")
async def export_vulnerabilities_csv(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export all discovered vulnerabilities to a CSV file."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    with get_sync_db() as sync_db:
        service = ReportService(sync_db)
        buffer = service.export_vulnerabilities_csv(scan_id)

    filename = f"vulnerabilities_{sanitize_filename(scan.name)}.csv"

    return StreamingResponse(
        buffer,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/{scan_id}/csv/ports", summary="Export ports CSV")
async def export_ports_csv(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export all discovered ports and services to a CSV file."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    with get_sync_db() as sync_db:
        service = ReportService(sync_db)
        buffer = service.export_ports_csv(scan_id)

    filename = f"ports_{sanitize_filename(scan.name)}.csv"

    return StreamingResponse(
        buffer,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/{scan_id}/csv/summary")
async def export_summary_csv(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export scan summary to CSV"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    with get_sync_db() as sync_db:
        service = ReportService(sync_db)
        buffer = service.export_scan_summary_csv(scan_id)

    filename = f"scan_summary_{sanitize_filename(scan.name)}.csv"

    return StreamingResponse(
        buffer,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
