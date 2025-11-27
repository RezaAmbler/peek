from pydantic import BaseModel, Field, validator
from uuid import UUID
from datetime import datetime
from typing import Optional, List
import ipaddress

class TargetInput(BaseModel):
    """A single IP target to scan."""
    ip_address: str = Field(..., description="IPv4 address to scan", json_schema_extra={"example": "192.168.1.1"})
    device_name: Optional[str] = Field(None, description="Friendly device name", json_schema_extra={"example": "web-server-01"})

    @validator('ip_address')
    def validate_ip(cls, v):
        try:
            ipaddress.IPv4Address(v)
        except ipaddress.AddressValueError:
            raise ValueError(f'Invalid IPv4 address: {v}')
        return v

class ScanCreate(BaseModel):
    """Create a new security scan with target IPs."""
    name: str = Field(..., min_length=1, max_length=200, description="Scan name", json_schema_extra={"example": "Weekly Network Scan"})
    description: Optional[str] = Field(None, max_length=1000, description="Scan description", json_schema_extra={"example": "Scanning production servers for vulnerabilities"})
    config_id: UUID = Field(..., description="ID of the scan configuration to use")
    targets: List[TargetInput] = Field(..., min_length=1, max_length=1000, description="List of IP targets to scan")
    baseline_scan_id: Optional[UUID] = Field(None, description="Compare results against this previous scan")

class ScanCreateFromCSV(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    config_id: UUID
    targets_csv: str  # CSV content: "device_name,ip_address\n..."
    baseline_scan_id: Optional[UUID] = None

class ScanUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    config_id: Optional[UUID] = None
    targets: Optional[List[TargetInput]] = Field(None, min_items=1, max_items=1000)
    baseline_scan_id: Optional[UUID] = None

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

    class Config:
        from_attributes = True

class ScanResponse(BaseModel):
    id: UUID
    user_id: UUID
    created_by_id: UUID
    config_id: UUID
    name: str
    description: Optional[str]
    status: str
    current_phase: str
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    progress_percent: float
    total_targets: int
    completed_targets: int
    failed_targets: int
    total_open_ports: int
    total_vulnerabilities: int
    baseline_scan_id: Optional[UUID]

    class Config:
        from_attributes = True

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
