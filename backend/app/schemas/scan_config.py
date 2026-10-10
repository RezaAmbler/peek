from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict
from datetime import datetime
from typing import Optional, List, Tuple, Dict
import re

from ..core.validators import validate_nmap_args, validate_nuclei_template_paths

# Timeout configuration per scan mode: (center, min, max) in seconds
# - Center: default value for the mode
# - Min: -60% from center
# - Max: +90% from center
TIMEOUT_CONFIG: Dict[str, Tuple[int, int, int]] = {
    "fast": (1200, 480, 2280),    # 20min center, 8min-38min range
    "deep": (3600, 1440, 6840),   # 60min center, 24min-114min range
}


def get_timeout_range(scan_mode: str) -> Tuple[int, int, int]:
    """Get (center, min, max) timeout values for a scan mode."""
    return TIMEOUT_CONFIG.get(scan_mode, TIMEOUT_CONFIG["deep"])


def validate_timeout_for_mode(scan_mode: str, timeout: int) -> None:
    """Raise ValueError if timeout is outside valid range for scan_mode."""
    center, min_val, max_val = get_timeout_range(scan_mode)
    if not (min_val <= timeout <= max_val):
        raise ValueError(
            f"host_timeout_seconds={timeout}s is outside valid range for '{scan_mode}' mode. "
            f"Valid range: {min_val}s - {max_val}s (default: {center}s)"
        )


class ScanConfigBase(BaseModel):
    """Base schema for scan configuration profiles."""
    name: str = Field(..., min_length=1, max_length=100, description="Configuration name", json_schema_extra={"example": "Production Scan Config"})
    description: Optional[str] = Field(None, max_length=500, description="Configuration description", json_schema_extra={"example": "Careful scan settings for production servers"})

    # Targets — list of IPs or hostnames to scan
    targets: List[str] = Field(default=[], description="List of IPs or hostnames to scan", json_schema_extra={"example": ["203.0.113.10", "10.0.0.1"]})

    # Scanning parameters
    masscan_rate: int = Field(default=1000, ge=100, le=100000, description="Masscan packets per second", json_schema_extra={"example": 1000})
    masscan_interface: Optional[str] = Field(None, max_length=50, description="Network interface for masscan", json_schema_extra={"example": "eth0"})
    nmap_args: List[str] = Field(default=["-sS", "-sV", "-sC", "-T2", "-Pn"], description="Nmap command arguments", json_schema_extra={"example": ["-sS", "-sV", "-sC", "-T2", "-Pn"]})
    ssh_ports: List[int] = Field(default=[22, 830], description="Ports to run ssh-audit on", json_schema_extra={"example": [22, 830]})

    # Port discovery settings
    discovery_top_ports: int = Field(default=1000, ge=100, le=10000, description="Number of top ports to scan during discovery")
    additional_ports: Optional[str] = Field(default="6379,11211,9200,27017,5984,9042,2375,2376,5672,15672,8080,8443,9000", description="Comma-separated list of additional ports to always scan")

    # Concurrency & Timeouts
    max_concurrent_hosts: int = Field(default=10, ge=1, le=100)
    max_concurrent_scans: int = Field(default=3, ge=1, le=10)
    host_timeout_seconds: Optional[int] = Field(default=None, description="Host timeout in seconds (auto-set based on scan_mode if not specified)")
    masscan_timeout_percent: float = Field(default=0.20, ge=0.05, le=0.50)
    nmap_timeout_percent: float = Field(default=0.70, ge=0.20, le=0.90)

    # Tool toggles
    enable_ssh_audit: bool = Field(default=True, description="Run ssh-audit on SSH ports")
    enable_nuclei: bool = Field(default=True, description="Run Nuclei vulnerability scanner")
    enable_nse: bool = Field(default=True, description="Run Nmap Scripting Engine (NSE) scripts")
    enable_sslscan: bool = Field(default=True, description="Run SSLScan for TLS/SSL analysis")
    enable_httpx: bool = Field(default=True, description="Run httpx HTTP prober with technology detection")
    httpx_timeout: int = Field(default=30, ge=5, le=120, description="httpx HTTP timeout per target (seconds)")
    httpx_tech_detect: bool = Field(default=True, description="Enable httpx technology fingerprinting")
    httpx_screenshots: bool = Field(default=False, description="Capture a screenshot of every web service (httpx + headless Chromium)")
    nuclei_severity: str = Field(default="critical,high,medium,low,info", description="Nuclei severity filter", json_schema_extra={"example": "critical,high,medium,low,info"})
    nuclei_templates: Optional[str] = Field(None, description="Custom Nuclei template paths")
    nuclei_timeout: int = Field(default=300, ge=60, le=1800, description="Nuclei timeout per target (seconds)")
    scan_mode: str = Field(default="deep", description="Scan mode: 'fast' (targeted CVEs) or 'deep' (comprehensive)", json_schema_extra={"example": "deep"})

    # Web scanning options
    enable_nikto: bool = Field(default=False, description="Run Nikto web server scanner")
    enable_zap: bool = Field(default=False, description="Run OWASP ZAP web application scanner")
    zap_scan_type: str = Field(default="baseline", description="ZAP scan type: 'baseline' or 'api'")
    zap_timeout: int = Field(default=300, ge=60, le=1800, description="ZAP scan timeout (seconds)")
    nikto_timeout: int = Field(default=120, ge=30, le=600, description="Nikto scan timeout (seconds)")
    target_urls: Optional[List[str]] = Field(None, description="URLs for web scanning (if different from discovered HTTP services)")

    # Endpoint discovery (Katana)
    enable_katana: bool = Field(default=False, description="Run Katana for endpoint discovery/crawling")
    katana_timeout: int = Field(default=120, ge=30, le=600, description="Katana timeout per target (seconds)")
    katana_max_depth: int = Field(default=3, ge=1, le=10, description="Katana crawl depth limit")
    katana_concurrency: int = Field(default=10, ge=1, le=50, description="Katana parallel requests")

    # TLS analysis (testssl.sh)
    enable_testssl: bool = Field(default=False, description="Run testssl.sh for deep TLS analysis")
    testssl_timeout: int = Field(default=180, ge=60, le=600, description="testssl.sh timeout per target (seconds)")

    # Nuclei endpoint mode (scans discovered endpoints)
    enable_nuclei_endpoints: bool = Field(default=False, description="Run Nuclei against discovered endpoints")
    nuclei_endpoint_severity: str = Field(default="critical,high,medium", description="Severity filter for endpoint nuclei scans")
    nuclei_endpoint_timeout: int = Field(default=600, ge=60, le=3600, description="Nuclei endpoint mode timeout (seconds)")

    # Advanced timeouts
    global_tool_timeout_seconds: Optional[int] = Field(None, ge=60, le=7200)
    parallelism_limit: Optional[int] = Field(None, ge=1, le=50)

    # Reporting
    highlight_ports: List[int] = Field(default=[22, 80, 443, 3389, 8443])
    email_on_completion: bool = False
    email_on_changes_only: bool = False

    # Scheduling (for automated recurring scans)
    schedule: Optional[str] = Field(None, description="Cron expression for scheduled runs", json_schema_extra={"example": "0 2 * * 0"})
    schedule_enabled: bool = Field(default=False, description="Whether scheduled runs are enabled")

    @field_validator('targets')
    @classmethod
    def validate_targets(cls, v: List[str]) -> List[str]:
        if v is None:
            return []
        # Basic validation - could add IP/hostname validation here
        return [t.strip() for t in v if t.strip()]

    @field_validator('ssh_ports', 'highlight_ports')
    @classmethod
    def validate_ports(cls, v: List[int]) -> List[int]:
        for port in v:
            if not (1 <= port <= 65535):
                raise ValueError(f'Port {port} out of valid range (1-65535)')
        return v

    @field_validator('nuclei_severity', 'nuclei_endpoint_severity')
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
        # Allow-list: the list ends up in nmap's argv (see core/validators.py)
        return validate_nmap_args(v)

    @field_validator('nuclei_templates')
    @classmethod
    def validate_nuclei_templates(cls, v: Optional[str]) -> Optional[str]:
        return validate_nuclei_template_paths(v)

    @field_validator('scan_mode')
    @classmethod
    def validate_scan_mode(cls, v: str) -> str:
        valid = {'fast', 'deep'}
        if v.lower() not in valid:
            raise ValueError(f"Invalid scan_mode '{v}'. Must be 'fast' or 'deep'")
        return v.lower()

    @model_validator(mode='after')
    def validate_timeout_range(self) -> 'ScanConfigBase':
        """Validate host_timeout_seconds against scan_mode and set default if not specified."""
        scan_mode = self.scan_mode
        center, min_val, max_val = get_timeout_range(scan_mode)

        # If timeout not specified, use center value for the mode
        if self.host_timeout_seconds is None:
            self.host_timeout_seconds = center
        else:
            # Validate timeout is within range for the mode
            validate_timeout_for_mode(scan_mode, self.host_timeout_seconds)

        return self


class ScanConfigCreate(ScanConfigBase):
    pass

class ScanConfigUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    targets: Optional[List[str]] = Field(None, description="List of IPs or hostnames to scan")
    masscan_rate: Optional[int] = Field(None, ge=100, le=100000)
    masscan_interface: Optional[str] = None
    nmap_args: Optional[List[str]] = None
    ssh_ports: Optional[List[int]] = None
    discovery_top_ports: Optional[int] = Field(None, ge=100, le=10000)
    additional_ports: Optional[str] = None
    max_concurrent_hosts: Optional[int] = Field(None, ge=1, le=100)
    max_concurrent_scans: Optional[int] = Field(None, ge=1, le=10)
    host_timeout_seconds: Optional[int] = Field(None, description="Host timeout in seconds (validated against scan_mode)")
    masscan_timeout_percent: Optional[float] = Field(None, ge=0.05, le=0.50)
    nmap_timeout_percent: Optional[float] = Field(None, ge=0.20, le=0.90)
    enable_ssh_audit: Optional[bool] = None
    enable_nuclei: Optional[bool] = None
    enable_nse: Optional[bool] = None
    enable_sslscan: Optional[bool] = None
    enable_httpx: Optional[bool] = None
    httpx_timeout: Optional[int] = Field(None, ge=5, le=120)
    httpx_tech_detect: Optional[bool] = None
    httpx_screenshots: Optional[bool] = None
    nuclei_severity: Optional[str] = None
    nuclei_templates: Optional[str] = None
    nuclei_timeout: Optional[int] = Field(None, ge=60, le=1800)
    scan_mode: Optional[str] = None
    enable_nikto: Optional[bool] = None
    enable_zap: Optional[bool] = None
    zap_scan_type: Optional[str] = None
    zap_timeout: Optional[int] = Field(None, ge=60, le=1800)
    nikto_timeout: Optional[int] = Field(None, ge=30, le=600)
    target_urls: Optional[List[str]] = None
    enable_katana: Optional[bool] = None
    katana_timeout: Optional[int] = Field(None, ge=30, le=600)
    katana_max_depth: Optional[int] = Field(None, ge=1, le=10)
    katana_concurrency: Optional[int] = Field(None, ge=1, le=50)
    enable_testssl: Optional[bool] = None
    testssl_timeout: Optional[int] = Field(None, ge=60, le=600)
    enable_nuclei_endpoints: Optional[bool] = None
    nuclei_endpoint_severity: Optional[str] = None
    nuclei_endpoint_timeout: Optional[int] = Field(None, ge=60, le=3600)
    global_tool_timeout_seconds: Optional[int] = Field(None, ge=60, le=7200)
    parallelism_limit: Optional[int] = Field(None, ge=1, le=50)
    highlight_ports: Optional[List[int]] = None
    email_on_completion: Optional[bool] = None
    email_on_changes_only: Optional[bool] = None
    schedule: Optional[str] = Field(None, description="Cron expression for scheduled runs")
    schedule_enabled: Optional[bool] = Field(None, description="Whether scheduled runs are enabled")

    # PATCH must enforce the same rules as create for values that reach a
    # scanner's command line.
    @field_validator('nmap_args')
    @classmethod
    def validate_nmap_args(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        return validate_nmap_args(v) if v is not None else None

    @field_validator('nuclei_templates')
    @classmethod
    def validate_nuclei_templates(cls, v: Optional[str]) -> Optional[str]:
        return validate_nuclei_template_paths(v)

    @field_validator('nuclei_severity', 'nuclei_endpoint_severity', check_fields=False)
    @classmethod
    def validate_severity(cls, v):
        if v is None:
            return v
        valid = {'info', 'low', 'medium', 'high', 'critical'}
        values = v if isinstance(v, list) else v.split(',')
        if not {str(s).strip().lower() for s in values}.issubset(valid):
            raise ValueError(f'Invalid severity values. Must be comma-separated: {", ".join(sorted(valid))}')
        return v

    @field_validator('masscan_interface')
    @classmethod
    def validate_interface(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', v):
            raise ValueError('Invalid network interface name')
        return v


class ScanConfigResponse(ScanConfigBase):
    id: str
    user_id: str
    organization_id: Optional[str] = None  # Always NULL in Phase 1-4
    created_at: datetime
    updated_at: datetime
    is_default: bool
    is_preset: bool = False  # System presets cannot be edited/deleted
    last_scheduled_run: Optional[datetime] = None
    run_count: int = 0  # Number of scans run with this config

    model_config = ConfigDict(from_attributes=True)

class ScanConfigListResponse(BaseModel):
    configs: List[ScanConfigResponse]
    total: int
