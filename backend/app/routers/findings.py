"""
Triage API — read and mutate the persistent, cross-scan state of findings.

FindingState is keyed by (config_id, fingerprint) and scoped/authorized the same
way comparisons are: access is granted to the owner of the ScanConfig (or an
admin). Setting status=false_positive / accepted_risk (or suppressed_until in the
future) makes the suppression-aware comparison stop re-surfacing the finding as
new on every scan.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional, List
from datetime import datetime

from ..database import get_db
from ..models import ScanConfig, FindingState, User
from ..models.finding_state import FINDING_STATUSES
from ..routers.auth import get_current_user
from ..schemas.finding_state import FindingStateResponse, FindingStateUpdate

router = APIRouter()


async def _authorize_config(db: AsyncSession, config_id: str, current_user: User) -> ScanConfig:
    """Load the config and verify the caller owns it (mirrors comparison auth)."""
    result = await db.execute(select(ScanConfig).where(ScanConfig.id == config_id))
    config = result.scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=404, detail="Scan configuration not found")
    if config.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to access this configuration")
    return config


@router.get("", response_model=List[FindingStateResponse])
@router.get("/", response_model=List[FindingStateResponse], include_in_schema=False)
async def list_finding_states(
    config_id: str = Query(..., description="Scan configuration to list triage state for"),
    status: Optional[str] = Query(None, description="Filter by triage status (open/triaged/false_positive/accepted_risk/fixed)"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List FindingState rows for a configuration, optionally filtered by status."""
    await _authorize_config(db, config_id, current_user)

    if status is not None and status not in FINDING_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status '{status}'. Allowed: {', '.join(FINDING_STATUSES)}",
        )

    query = select(FindingState).where(FindingState.config_id == config_id)
    if status is not None:
        query = query.where(FindingState.status == status)
    query = query.order_by(FindingState.last_seen_at.desc())

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{config_id}/{fingerprint}", response_model=FindingStateResponse)
async def get_finding_state(
    config_id: str,
    fingerprint: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the triage state of a single finding by (config_id, fingerprint)."""
    await _authorize_config(db, config_id, current_user)

    result = await db.execute(
        select(FindingState).where(
            FindingState.config_id == config_id,
            FindingState.fingerprint == fingerprint,
        )
    )
    state = result.scalar_one_or_none()
    if not state:
        raise HTTPException(status_code=404, detail="Finding state not found")
    return state


@router.patch("/{config_id}/{fingerprint}", response_model=FindingStateResponse)
async def update_finding_state(
    config_id: str,
    fingerprint: str,
    payload: FindingStateUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Set triage status/owner/notes/suppressed_until for a finding.

    404 if the finding state does not exist yet (states are created by the
    post-scan upsert, not by the API).
    """
    await _authorize_config(db, config_id, current_user)

    result = await db.execute(
        select(FindingState).where(
            FindingState.config_id == config_id,
            FindingState.fingerprint == fingerprint,
        )
    )
    state = result.scalar_one_or_none()
    if not state:
        raise HTTPException(status_code=404, detail="Finding state not found")

    # Apply only explicitly-provided fields (status already validated by schema).
    data = payload.model_dump(exclude_unset=True)
    for field in ("status", "owner", "triage_notes", "suppressed_until"):
        if field in data:
            setattr(state, field, data[field])

    await db.commit()
    await db.refresh(state)
    return state
