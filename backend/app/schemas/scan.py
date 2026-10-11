from pydantic import BaseModel, Field, field_validator, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional, List
import ipaddress


class ScanCreate(BaseModel):
    """Create a new scan run from a configuration.

    Targets can be specified here to override config.targets, or left empty to use config targets.
    """
    config_id: UUID = Field(..., description="ID of the scan configuration to use")
    name: Optional[str] = Field(None, max_length=200, description="Optional scan name. Auto-generated as 'Run #N — Date' if not provided")
    description: Optional[str] = Field(None, max_length=1000, description="Scan description")
    targets: Optional[List[str]] = Field(None, description="Override targets. If not provided, uses config.targets")


class ScanUpdate(BaseModel):
    """Update scan metadata (limited — most properties are immutable)."""
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)

class TargetResponse(BaseModel):
    id: UUID
    device_name: Optional[str]
    ip_address: str
    status: str
    error_message: Optional[str]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    duration_seconds: Optional[float]
    sequence: int

    model_config = ConfigDict(from_attributes=True)

class ScanResponse(BaseModel):
    id: UUID
    user_id: UUID
    created_by_id: UUID
    config_id: UUID
    config_name: str = ""  # Denormalized for display
    config_hash: Optional[str] = None  # SHA256 of comparable config subset; identical hashes are comparable
    run_number: int = 1
    name: Optional[str]  # May be None, display as "Run #N — Date" if so
    description: Optional[str]
    status: str
    current_phase: str
    error_message: Optional[str] = None  # Why the scan failed (status == failed)
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    progress_percent: float
    total_targets: int
    completed_targets: int
    failed_targets: int
    total_open_ports: int
    total_vulnerabilities: int

    model_config = ConfigDict(from_attributes=True)

    @property
    def display_name(self) -> str:
        """Return name for display, auto-generating if not set."""
        if self.name:
            return self.name
        return f"Run #{self.run_number} — {self.created_at.strftime('%b %d, %Y %H:%M')}"

class ScanDetailResponse(ScanResponse):
    targets: List[TargetResponse]
    phase_stats: Optional[dict]

class ScanListResponse(BaseModel):
    scans: List[ScanResponse]
    total: int
    page: int
    pages: int

class ScanProgress(BaseModel):
    total_targets: int
    completed_targets: int
    current_phase: str
    percent_complete: float
