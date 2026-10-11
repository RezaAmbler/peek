from sqlalchemy import Column, String, Boolean, Integer, Float, DateTime, ForeignKey, Enum, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum
from ..database import Base
from ..core.timeutil import utcnow

class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ScanPhase(str, enum.Enum):
    PENDING = "pending"
    NMAP_DISCOVERY = "nmap_discovery"
    NMAP = "nmap"
    HTTPX = "httpx"  # HTTP probing with technology detection
    KATANA = "katana"  # Endpoint discovery/crawling
    SSH_AUDIT = "ssh_audit"
    NUCLEI = "nuclei"
    NUCLEI_ENDPOINTS = "nuclei_endpoints"  # Nuclei scanning of discovered endpoints
    NSE = "nse"
    SSLSCAN = "sslscan"
    TESTSSL = "testssl"  # Deep TLS analysis with testssl.sh
    NIKTO = "nikto"
    ZAP = "zap"
    COMPLETED = "completed"
    FAILED = "failed"

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Ownership
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=True, index=True)

    # Configuration used for this scan
    config_id = Column(String(36), ForeignKey("scan_configs.id"), nullable=False, index=True)

    # Frozen snapshot of the comparable-subset of ScanConfig fields at scan-creation time.
    # config_hash is the SHA256 of canonical JSON(config_snapshot). Two scans are comparable
    # only if their config_hashes match — see services/config_snapshot.py.
    config_snapshot = Column(JSON, nullable=True)
    config_hash = Column(String(64), nullable=True, index=True)

    # Run tracking — auto-incremented per config
    run_number = Column(Integer, nullable=False, default=1)

    # Basic info — name is optional, auto-generated as "Run #N — Date" if not provided
    name = Column(String, nullable=True)
    description = Column(String, nullable=True)

    # Status tracking
    status = Column(String, default=ScanStatus.PENDING.value, nullable=False, index=True)
    current_phase = Column(String, default=ScanPhase.PENDING.value, nullable=False)
    celery_task_id = Column(String, nullable=True)
    # Why the scan failed (set together with status=failed); shown in the UI
    error_message = Column(String, nullable=True)

    # Timing
    created_at = Column(DateTime, default=utcnow, nullable=False)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    # Progress tracking (for polling)
    progress_percent = Column(Float, default=0.0, nullable=False)
    progress_updated_at = Column(DateTime, nullable=True)
    phase_stats = Column(JSON, nullable=True)  # {"masscan": {"completed": 5, "total": 10}, ...}

    # Statistics (computed after scan completes)
    total_targets = Column(Integer, default=0, nullable=False)
    completed_targets = Column(Integer, default=0, nullable=False)
    failed_targets = Column(Integer, default=0, nullable=False)
    total_open_ports = Column(Integer, default=0, nullable=False)
    total_vulnerabilities = Column(Integer, default=0, nullable=False)

    # Relationships
    user = relationship("User", foreign_keys=[user_id], backref="scans")
    created_by = relationship("User", foreign_keys=[created_by_id])
    config = relationship("ScanConfig", back_populates="scans")
    targets = relationship("ScanTarget", back_populates="scan", cascade="all, delete-orphan")
    discovered_endpoints = relationship("DiscoveredEndpoint", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
