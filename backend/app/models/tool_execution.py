from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum
from ..database import Base

class ToolName(str, enum.Enum):
    MASSCAN = "masscan"
    NMAP = "nmap"
    SSH_AUDIT = "ssh-audit"
    NUCLEI = "nuclei"

class RawFormat(str, enum.Enum):
    JSON = "json"
    JSONL = "jsonl"
    XML = "xml"
    TEXT = "text"

class ToolExecution(Base):
    __tablename__ = "tool_executions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_target_id = Column(String(36), ForeignKey("scan_targets.id", ondelete="CASCADE"), nullable=False, index=True)
    port_id = Column(String(36), ForeignKey("ports.id", ondelete="SET NULL"), nullable=True, index=True)

    # Tool info
    tool_name = Column(String, nullable=False, index=True)  # masscan, nmap, ssh-audit, nuclei

    # Timing
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True)

    # Execution details
    command_line = Column(Text, nullable=True)  # Exact command executed
    exit_code = Column(Integer, nullable=True)

    # Raw storage (critical for diffs and debugging)
    raw_output = Column(Text, nullable=True)  # Tool output (truncated to 50KB if larger)
    raw_format = Column(String, nullable=True)  # json, jsonl, xml, text
    artifact_path = Column(String, nullable=True)  # Full output path when raw_output is truncated

    # Parsed output (for debugging parser logic)
    parsed_output = Column(JSON, nullable=True)

    # Parser versioning (for reprocessing)
    parser_version = Column(String, default="1.0.0", nullable=False)
    needs_reparse = Column(Integer, default=0, nullable=False)  # SQLite doesn't have bool, use int

    # Error tracking
    error_message = Column(String, nullable=True)

    # Relationships
    target = relationship("ScanTarget", back_populates="tool_executions")
    port_record = relationship("Port", foreign_keys=[port_id])
