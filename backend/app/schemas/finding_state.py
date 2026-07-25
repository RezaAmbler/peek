"""Pydantic schemas for the triage (FindingState) API."""

from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional

from ..models.finding_state import FINDING_STATUSES


class FindingStateResponse(BaseModel):
    """A single finding's persistent triage state."""
    id: str
    config_id: str
    organization_id: Optional[str] = None
    fingerprint: str
    cve_id: Optional[str] = None
    name: Optional[str] = None
    status: str
    owner: Optional[str] = None
    triage_notes: Optional[str] = None
    suppressed_until: Optional[datetime] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    first_seen_scan_id: Optional[str] = None
    last_seen_scan_id: Optional[str] = None

    class Config:
        from_attributes = True


class FindingStateUpdate(BaseModel):
    """Triage mutation. All fields optional; only provided fields are applied."""
    status: Optional[str] = Field(
        None, description=f"One of: {', '.join(FINDING_STATUSES)}"
    )
    owner: Optional[str] = Field(None, max_length=200)
    triage_notes: Optional[str] = Field(None, max_length=5000)
    suppressed_until: Optional[datetime] = Field(
        None, description="Suppress this finding until this UTC time (time-boxed accepted risk)"
    )

    @field_validator("status")
    @classmethod
    def _validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in FINDING_STATUSES:
            raise ValueError(
                f"Invalid status '{v}'. Allowed: {', '.join(FINDING_STATUSES)}"
            )
        return v
