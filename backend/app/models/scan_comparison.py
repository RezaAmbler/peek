from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from ..database import Base

class ScanComparison(Base):
    __tablename__ = "scan_comparisons"

    id = Column(String(36), primary_key=True)

    # Scans being compared
    baseline_scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    current_scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)

    # Summary statistics
    total_changes = Column(Integer, default=0, nullable=False)
    new_ports = Column(Integer, default=0, nullable=False)
    closed_ports = Column(Integer, default=0, nullable=False)
    version_changes = Column(Integer, default=0, nullable=False)
    new_vulnerabilities = Column(Integer, default=0, nullable=False)
    fixed_vulnerabilities = Column(Integer, default=0, nullable=False)

    # Change severity breakdown
    critical_changes = Column(Integer, default=0, nullable=False)
    high_changes = Column(Integer, default=0, nullable=False)
    medium_changes = Column(Integer, default=0, nullable=False)
    low_changes = Column(Integer, default=0, nullable=False)
    positive_changes = Column(Integer, default=0, nullable=False)  # Improvements

    # Detailed changes (JSON array)
    changes = Column(JSON, nullable=False)  # List of change objects

    # Summary text
    summary = Column(Text, nullable=True)

    # Relationships
    baseline_scan = relationship("Scan", foreign_keys=[baseline_scan_id], backref="comparisons_as_baseline")
    current_scan = relationship("Scan", foreign_keys=[current_scan_id], backref="comparisons_as_current")
    created_by = relationship("User")
