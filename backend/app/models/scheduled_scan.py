from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, JSON, Integer
from sqlalchemy.orm import relationship
from datetime import datetime
from ..database import Base

class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"

    id = Column(String(36), primary_key=True)

    # Ownership
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    organization_id = Column(String(36), nullable=True, index=True)

    # Schedule configuration
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    cron_expression = Column(String, nullable=False)  # e.g., "0 2 * * 1"
    timezone = Column(String, default="UTC", nullable=False)  # e.g., "America/Los_Angeles"

    # Scan configuration
    config_id = Column(String(36), ForeignKey("scan_configs.id"), nullable=False)
    targets = Column(JSON, nullable=False)  # List of {ip_address, device_name}

    # Comparison settings
    auto_compare = Column(Boolean, default=True, nullable=False)
    baseline_scan_id = Column(String(36), ForeignKey("scans.id"), nullable=True)
    compare_with_previous = Column(Boolean, default=True, nullable=False)  # Compare with last run

    # Notification settings
    email_on_completion = Column(Boolean, default=False, nullable=False)
    email_on_changes_only = Column(Boolean, default=True, nullable=False)
    email_recipients = Column(JSON, nullable=True)  # List of email addresses
    alert_on_critical = Column(Boolean, default=True, nullable=False)
    alert_on_new_vulns = Column(Boolean, default=True, nullable=False)

    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    last_run_at = Column(DateTime, nullable=True)
    last_run_scan_id = Column(String(36), ForeignKey("scans.id"), nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    total_runs = Column(Integer, default=0, nullable=False)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", foreign_keys=[user_id], backref="scheduled_scans")
    created_by = relationship("User", foreign_keys=[created_by_id])
    config = relationship("ScanConfig")
    baseline_scan = relationship("Scan", foreign_keys=[baseline_scan_id])
    last_run_scan = relationship("Scan", foreign_keys=[last_run_scan_id])
