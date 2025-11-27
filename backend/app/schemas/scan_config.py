from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional, List

class ScanConfigBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)

    # Scanning parameters
    masscan_rate: int = Field(default=1000, ge=100, le=100000)
    masscan_interface: Optional[str] = Field(None, max_length=50)
    nmap_args: List[str] = Field(default=["-sS", "-sV", "-sC", "-T2", "-Pn"])
    ssh_ports: List[int] = Field(default=[22, 830])

    # Concurrency & Timeouts
    max_concurrent_hosts: int = Field(default=10, ge=1, le=100)
    max_concurrent_scans: int = Field(default=3, ge=1, le=10)
    host_timeout_seconds: int = Field(default=1200, ge=60, le=7200)
    masscan_timeout_percent: float = Field(default=0.20, ge=0.05, le=0.50)
    nmap_timeout_percent: float = Field(default=0.70, ge=0.20, le=0.90)

    # Tool toggles
    enable_ssh_audit: bool = True
    enable_nuclei: bool = False
    nuclei_severity: str = Field(default="critical,high,medium")
    nuclei_templates: Optional[str] = None
    nuclei_timeout: int = Field(default=300, ge=60, le=1800)

    # Advanced timeouts
    global_tool_timeout_seconds: Optional[int] = Field(None, ge=60, le=7200)
    parallelism_limit: Optional[int] = Field(None, ge=1, le=50)

    # Reporting
    highlight_ports: List[int] = Field(default=[22, 80, 443, 3389, 8443])
    email_on_completion: bool = False
    email_on_changes_only: bool = False

    @field_validator('ssh_ports', 'highlight_ports')
    @classmethod
    def validate_ports(cls, v: List[int]) -> List[int]:
        for port in v:
            if not (1 <= port <= 65535):
                raise ValueError(f'Port {port} out of valid range (1-65535)')
        return v

    @field_validator('nuclei_severity')
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid = {'info', 'low', 'medium', 'high', 'critical'}
        severities = set(s.strip().lower() for s in v.split(','))
        if not severities.issubset(valid):
            raise ValueError(f'Invalid severity values. Must be comma-separated: {", ".join(valid)}')
        return v

    @field_validator('nmap_args')
    @classmethod
    def validate_nmap_args(cls, v: List[str]) -> List[str]:
        if not v or not isinstance(v, list):
            raise ValueError('nmap_args must be a non-empty list')
        return v

class ScanConfigCreate(ScanConfigBase):
    pass

class ScanConfigUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    masscan_rate: Optional[int] = Field(None, ge=100, le=100000)
    masscan_interface: Optional[str] = None
    nmap_args: Optional[List[str]] = None
    ssh_ports: Optional[List[int]] = None
    max_concurrent_hosts: Optional[int] = Field(None, ge=1, le=100)
    max_concurrent_scans: Optional[int] = Field(None, ge=1, le=10)
    host_timeout_seconds: Optional[int] = Field(None, ge=60, le=7200)
    masscan_timeout_percent: Optional[float] = Field(None, ge=0.05, le=0.50)
    nmap_timeout_percent: Optional[float] = Field(None, ge=0.20, le=0.90)
    enable_ssh_audit: Optional[bool] = None
    enable_nuclei: Optional[bool] = None
    nuclei_severity: Optional[str] = None
    nuclei_templates: Optional[str] = None
    nuclei_timeout: Optional[int] = Field(None, ge=60, le=1800)
    global_tool_timeout_seconds: Optional[int] = Field(None, ge=60, le=7200)
    parallelism_limit: Optional[int] = Field(None, ge=1, le=50)
    highlight_ports: Optional[List[int]] = None
    email_on_completion: Optional[bool] = None
    email_on_changes_only: Optional[bool] = None

class ScanConfigResponse(ScanConfigBase):
    id: str
    user_id: str
    organization_id: Optional[str] = None  # Always NULL in Phase 1-4
    created_at: datetime
    updated_at: datetime
    is_default: bool

    class Config:
        from_attributes = True

class ScanConfigListResponse(BaseModel):
    configs: List[ScanConfigResponse]
    total: int
