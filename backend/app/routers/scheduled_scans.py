from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from ..database import get_db
from ..models import ScheduledScan, User
from ..schemas.scheduled_scan import (
    ScheduledScanCreate,
    ScheduledScanUpdate,
    ScheduledScanResponse,
    ScheduledScanListResponse
)
from ..routers.auth import get_current_user
from ..tasks.scheduled_scan_tasks import calculate_next_run
from datetime import datetime
import uuid

router = APIRouter()

@router.get("", response_model=ScheduledScanListResponse)
async def list_scheduled_scans(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List all scheduled scans for the current user"""
    result = await db.execute(
        select(ScheduledScan)
        .where(ScheduledScan.user_id == str(current_user.id))
        .order_by(ScheduledScan.created_at.desc())
    )
    scheduled_scans = result.scalars().all()

    return ScheduledScanListResponse(
        scheduled_scans=scheduled_scans,
        total=len(scheduled_scans)
    )

@router.get("/{scheduled_scan_id}", response_model=ScheduledScanResponse)
async def get_scheduled_scan(
    scheduled_scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get a single scheduled scan by ID"""
    result = await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == scheduled_scan_id)
    )
    scheduled_scan = result.scalar_one_or_none()

    if not scheduled_scan:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    if scheduled_scan.user_id != str(current_user.id) and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    return scheduled_scan

@router.post("", response_model=ScheduledScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scheduled_scan(
    scheduled_scan_data: ScheduledScanCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new scheduled scan"""
    # Calculate first run time
    next_run = calculate_next_run(
        scheduled_scan_data.cron_expression,
        scheduled_scan_data.timezone
    )

    # Create scheduled scan
    scheduled_scan = ScheduledScan(
        id=str(uuid.uuid4()),
        user_id=str(current_user.id),
        created_by_id=str(current_user.id),
        organization_id=None,
        next_run_at=next_run,
        **scheduled_scan_data.model_dump()
    )

    db.add(scheduled_scan)
    await db.commit()
    await db.refresh(scheduled_scan)

    return scheduled_scan

@router.patch("/{scheduled_scan_id}", response_model=ScheduledScanResponse)
async def update_scheduled_scan(
    scheduled_scan_id: str,
    scheduled_scan_data: ScheduledScanUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update a scheduled scan"""
    result = await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == scheduled_scan_id)
    )
    scheduled_scan = result.scalar_one_or_none()

    if not scheduled_scan:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    if scheduled_scan.user_id != str(current_user.id) and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Update fields
    update_data = scheduled_scan_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(scheduled_scan, field, value)

    # Recalculate next run if cron changed
    if 'cron_expression' in update_data or 'timezone' in update_data:
        scheduled_scan.next_run_at = calculate_next_run(
            scheduled_scan.cron_expression,
            scheduled_scan.timezone
        )

    await db.commit()
    await db.refresh(scheduled_scan)

    return scheduled_scan

@router.delete("/{scheduled_scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scheduled_scan(
    scheduled_scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete a scheduled scan"""
    result = await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == scheduled_scan_id)
    )
    scheduled_scan = result.scalar_one_or_none()

    if not scheduled_scan:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    if scheduled_scan.user_id != str(current_user.id) and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    await db.delete(scheduled_scan)
    await db.commit()

@router.post("/{scheduled_scan_id}/pause", response_model=ScheduledScanResponse)
async def pause_scheduled_scan(
    scheduled_scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Pause a scheduled scan"""
    result = await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == scheduled_scan_id)
    )
    scheduled_scan = result.scalar_one_or_none()

    if not scheduled_scan:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    if scheduled_scan.user_id != str(current_user.id) and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    scheduled_scan.is_active = False
    await db.commit()
    await db.refresh(scheduled_scan)

    return scheduled_scan

@router.post("/{scheduled_scan_id}/resume", response_model=ScheduledScanResponse)
async def resume_scheduled_scan(
    scheduled_scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Resume a paused scheduled scan"""
    result = await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == scheduled_scan_id)
    )
    scheduled_scan = result.scalar_one_or_none()

    if not scheduled_scan:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    if scheduled_scan.user_id != str(current_user.id) and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    scheduled_scan.is_active = True

    # Recalculate next run
    scheduled_scan.next_run_at = calculate_next_run(
        scheduled_scan.cron_expression,
        scheduled_scan.timezone
    )

    await db.commit()
    await db.refresh(scheduled_scan)

    return scheduled_scan

@router.post("/{scheduled_scan_id}/run-now", response_model=dict)
async def run_scheduled_scan_now(
    scheduled_scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Manually trigger a scheduled scan to run immediately"""
    result = await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == scheduled_scan_id)
    )
    scheduled_scan = result.scalar_one_or_none()

    if not scheduled_scan:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    if scheduled_scan.user_id != str(current_user.id) and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Queue execution
    from ..tasks.scheduled_scan_tasks import execute_scheduled_scan
    task = execute_scheduled_scan.delay(scheduled_scan_id)

    return {
        "message": "Scheduled scan queued for immediate execution",
        "task_id": task.id
    }
