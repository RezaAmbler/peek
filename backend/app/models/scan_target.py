from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum
from ..database import Base

class TargetStatus(str, enum.Enum):
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"

class ScanTarget(Base):
    __tablename__ = "scan_targets"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)

    # Target info
    device_name = Column(String, nullable=True)  # Optional friendly name from CSV
    ip_address = Column(String, nullable=False, index=True)

    # Status
    status = Column(String, default=TargetStatus.PENDING.value, nullable=False, index=True)
    error_message = Column(String, nullable=True)

    # Timing
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)

    # Display order
    sequence = Column(Integer, nullable=False, default=0)

    # Relationships
    scan = relationship("Scan", back_populates="targets")
    tool_executions = relationship("ToolExecution", back_populates="target", cascade="all, delete-orphan")
    ports = relationship("Port", back_populates="target", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="target", cascade="all, delete-orphan")
