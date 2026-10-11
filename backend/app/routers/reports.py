import re
from typing import Literal, Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..database import get_db
from ..models import Scan, User
from ..routers.auth import get_current_user
from ..services.report_service import ReportService, COMPARISON_CSV_CATEGORIES
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

async def _authorized_comparison(comparison_id: str, current_user: User, db: AsyncSession):
    """Load a comparison the user may read: admins, or the owner of the scans it compares."""
    from ..models import ScanComparison

    result = await db.execute(select(ScanComparison).where(ScanComparison.id == comparison_id))
    comparison = result.scalar_one_or_none()

    if not comparison:
        raise HTTPException(status_code=404, detail="Comparison not found")

    if not current_user.is_admin:
        scans_result = await db.execute(
            select(Scan).where(Scan.id.in_([comparison.baseline_scan_id, comparison.current_scan_id]))
        )
        scans = scans_result.scalars().all()
        # A report shows data from both scans, so owning only one of them is not enough
        if not scans or any(scan.user_id != current_user.id for scan in scans):
            raise HTTPException(status_code=403, detail="Not authorized")

    return comparison

def _comparison_download(body, media_type: str, comparison_id: str, name: str, extension: str):
    filename = f"{name}_{sanitize_filename(comparison_id[:8])}.{extension}"
    return StreamingResponse(
        body,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/comparison/{comparison_id}/pdf", summary="Comparison report PDF")
@router.get("/comparison/{comparison_id}/pdf/detailed", summary="Comparison detailed report PDF")
async def get_comparison_report_pdf(
    comparison_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate the detailed comparison PDF listing the changes of every section."""
    await _authorized_comparison(comparison_id, current_user, db)

    with get_sync_db() as sync_db:
        service = ReportService(sync_db)
        buffer = service.generate_comparison_report_pdf(comparison_id)

    return _comparison_download(buffer, "application/pdf", comparison_id, "comparison_report", "pdf")

@router.get("/comparison/{comparison_id}/pdf/executive", summary="Comparison executive summary PDF")
async def get_comparison_executive_pdf(
    comparison_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate a short comparison PDF: the counts and the most severe changes of each kind."""
    await _authorized_comparison(comparison_id, current_user, db)

    with get_sync_db() as sync_db:
        service = ReportService(sync_db)
        buffer = service.generate_comparison_report_pdf(comparison_id, executive=True)

    return _comparison_download(buffer, "application/pdf", comparison_id, "comparison_executive_summary", "pdf")

@router.get("/comparison/{comparison_id}/html", summary="Comparison HTML report")
async def get_comparison_html_report(
    comparison_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate the comparison report as a standalone HTML page."""
    await _authorized_comparison(comparison_id, current_user, db)

    with get_sync_db() as sync_db:
        service = ReportService(sync_db)
        html = service.generate_comparison_html_report(comparison_id)

    return _comparison_download(iter([html]), "text/html", comparison_id, "comparison_report", "html")

@router.get("/comparison/{comparison_id}/csv/changes", summary="Export comparison changes CSV")
async def export_comparison_changes_csv(
    comparison_id: str,
    category: Optional[Literal[COMPARISON_CSV_CATEGORIES]] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export the changes of a comparison to a CSV file, optionally only one category."""
    await _authorized_comparison(comparison_id, current_user, db)

    with get_sync_db() as sync_db:
        service = ReportService(sync_db)
        buffer = service.export_comparison_changes_csv(comparison_id, category)

    name = f"comparison_{category}_changes" if category else "comparison_changes"
    return _comparison_download(buffer, "text/csv", comparison_id, name, "csv")

@router.get("/comparison/{comparison_id}/csv/summary", summary="Export comparison summary CSV")
async def export_comparison_summary_csv(
    comparison_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export the comparison's scans and change counts to a CSV file."""
    await _authorized_comparison(comparison_id, current_user, db)

    with get_sync_db() as sync_db:
        service = ReportService(sync_db)
        buffer = service.export_comparison_summary_csv(comparison_id)

    return _comparison_download(buffer, "text/csv", comparison_id, "comparison_summary", "csv")

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
