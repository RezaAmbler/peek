from sqlalchemy import Column, String, Boolean, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
from ..database import Base

class SSHAudit(Base):
    __tablename__ = "ssh_audits"

    id = Column(String(36), primary_key=True)
    port_id = Column(String(36), ForeignKey("ports.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    tool_execution_id = Column(String(36), ForeignKey("tool_executions.id", ondelete="CASCADE"), nullable=True)

    # SSH server info
    banner = Column(String, nullable=True)  # e.g., "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    ssh_version = Column(String, nullable=True)  # "2.0" or "1.5"

    # Algorithms (stored as JSON arrays)
    key_exchange_algorithms = Column(JSON, nullable=True)  # ["diffie-hellman-group14-sha256", ...]
    host_key_algorithms = Column(JSON, nullable=True)      # ["ssh-rsa", "ssh-ed25519", ...]
    encryption_algorithms = Column(JSON, nullable=True)    # ["aes128-ctr", "aes256-gcm@openssh.com", ...]
    mac_algorithms = Column(JSON, nullable=True)           # ["hmac-sha2-256", ...]
    compression_algorithms = Column(JSON, nullable=True)   # ["none", "zlib@openssh.com"]

    # Security findings
    vulnerabilities = Column(JSON, nullable=True)  # [{"severity": "critical", "description": "..."}]
    recommendations = Column(JSON, nullable=True)  # [{"action": "remove", "item": "weak-cipher"}]

    # Connection status
    connection_failed = Column(Boolean, default=False, nullable=False)
    failure_reason = Column(String, nullable=True)

    # Relationships
    port = relationship("Port", back_populates="ssh_audit")
    tool_execution = relationship("ToolExecution")
