from sqlalchemy import Column, String, Boolean, Integer, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from ..database import Base

class ScanConfig(Base):
    __tablename__ = "scan_configs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Ownership
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)

    # Future org-level configs (nullable, always NULL in Phase 1-4)
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=True, index=True)

    # Basic info
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)

    # Scanning parameters
    masscan_rate = Column(Integer, default=1000, nullable=False)  # PPS
    masscan_interface = Column(String, nullable=True)  # e.g., "en0", "eth0"
    nmap_args = Column(JSON, default=lambda: ["-sS", "-sV", "-sC", "-T2", "-Pn"], nullable=False)
    ssh_ports = Column(JSON, default=lambda: [22, 830], nullable=False)

    # Concurrency & Timeouts
    max_concurrent_hosts = Column(Integer, default=10, nullable=False)
    max_concurrent_scans = Column(Integer, default=3, nullable=False)
    host_timeout_seconds = Column(Integer, default=1200, nullable=False)
    masscan_timeout_percent = Column(Float, default=0.20, nullable=False)
    nmap_timeout_percent = Column(Float, default=0.70, nullable=False)

    # Tool toggles
    enable_ssh_audit = Column(Boolean, default=True, nullable=False)
    enable_nuclei = Column(Boolean, default=False, nullable=False)
    nuclei_severity = Column(String, default="critical,high,medium,low,info", nullable=False)
    nuclei_templates = Column(String, nullable=True)  # Path to custom templates
    nuclei_timeout = Column(Integer, default=300, nullable=False)
    scan_mode = Column(String, default="deep", nullable=False)  # 'fast' or 'deep'

    # Advanced timeouts
    global_tool_timeout_seconds = Column(Integer, nullable=True)
    parallelism_limit = Column(Integer, nullable=True)  # If null, uses max_concurrent_hosts

    # Reporting
    highlight_ports = Column(JSON, default=lambda: [22, 80, 443, 3389, 8443], nullable=False)
    email_on_completion = Column(Boolean, default=False, nullable=False)
    email_on_changes_only = Column(Boolean, default=False, nullable=False)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    is_default = Column(Boolean, default=False, nullable=False)

    # Relationships
    user = relationship("User", back_populates="scan_configs")
