"""
DiscoveredEndpoint Model

Stores endpoints discovered during scanning (via Katana, httpx, etc.)
for vulnerability scanning and cross-run comparison.
"""

from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from ..database import Base
from ..core.timeutil import utcnow


class DiscoveredEndpoint(Base):
    __tablename__ = "discovered_endpoints"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Relationships
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_target_id = Column(String(36), ForeignKey("scan_targets.id", ondelete="CASCADE"), nullable=False, index=True)
    port_id = Column(String(36), ForeignKey("ports.id", ondelete="SET NULL"), nullable=True, index=True)
    tool_execution_id = Column(String(36), ForeignKey("tool_executions.id", ondelete="SET NULL"), nullable=True)

    # URL fields
    url = Column(String, nullable=False)  # Original URL as discovered
    normalized_url = Column(String, nullable=False)  # Canonical form for deduplication
    scheme = Column(String(10), nullable=False)  # http, https
    host = Column(String, nullable=False)  # Hostname
    port = Column(Integer, nullable=True)  # Explicit port (null for default 80/443)
    path = Column(String, nullable=False, default="/")  # URL path
    query = Column(String, nullable=True)  # Query string

    # HTTP method
    method = Column(String(10), nullable=False, default="GET")

    # Response metadata (populated if available)
    status_code = Column(Integer, nullable=True)
    content_type = Column(String, nullable=True)
    content_length = Column(Integer, nullable=True)

    # Discovery metadata
    depth = Column(Integer, nullable=False, default=0)  # Crawl depth from entry point
    source_tool = Column(String(50), nullable=False)  # katana, httpx, nuclei, etc.

    # Cross-run comparison (Phase 3 ready)
    content_hash = Column(String(32), nullable=True, index=True)  # For comparing content across runs

    # Timestamps
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="discovered_endpoints")
    target = relationship("ScanTarget", back_populates="discovered_endpoints")
    port_record = relationship("Port", foreign_keys=[port_id])
    tool_execution = relationship("ToolExecution", foreign_keys=[tool_execution_id])

    # Constraints and indexes
    __table_args__ = (
        # Prevent duplicate endpoints within same scan (same URL + method)
        UniqueConstraint('scan_id', 'normalized_url', 'method', name='uq_scan_endpoint_method'),
        # Efficient queries by scan and host
        Index('ix_discovered_endpoints_scan_host', 'scan_id', 'host'),
    )

    def __repr__(self):
        return f"<DiscoveredEndpoint {self.method} {self.url}>"
