from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, JSON, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from ..database import Base

class Port(Base):
    __tablename__ = "ports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_target_id = Column(String(36), ForeignKey("scan_targets.id", ondelete="CASCADE"), nullable=False, index=True)
    tool_execution_id = Column(String(36), ForeignKey("tool_executions.id", ondelete="CASCADE"), nullable=True)

    # Port info
    port = Column(Integer, nullable=False, index=True)
    protocol = Column(String, default="tcp", nullable=False)  # tcp, udp
    state = Column(String, nullable=False)  # open, closed, filtered

    # Service info (from nmap)
    service_name = Column(String, nullable=True)
    product = Column(String, nullable=True)
    version = Column(String, nullable=True)
    extra_info = Column(JSON, nullable=True)  # NSE scripts, etc.

    # Traceability
    discovered_by = Column(String, nullable=False)  # masscan, nmap

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    target = relationship("ScanTarget", back_populates="ports")
    tool_execution = relationship("ToolExecution", foreign_keys=[tool_execution_id])
    httpx_results = relationship("HttpxResult", back_populates="port_record", cascade="all, delete-orphan", passive_deletes=True)
    nse_findings = relationship("NseFinding", back_populates="port", cascade="all, delete-orphan", passive_deletes=True)
    ssh_audit = relationship("SSHAudit", back_populates="port", uselist=False, cascade="all, delete-orphan", passive_deletes=True)
    sslscan_result = relationship("SslScanResult", back_populates="port", uselist=False, cascade="all, delete-orphan", passive_deletes=True)

    # Composite unique constraint
    __table_args__ = (
        UniqueConstraint('scan_target_id', 'port', 'protocol', name='uq_target_port_protocol'),
    )
