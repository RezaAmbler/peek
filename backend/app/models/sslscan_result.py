from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, JSON, Text, DateTime
from sqlalchemy.orm import relationship
from ..database import Base


class SslScanResult(Base):
    """
    Stores sslscan TLS/SSL analysis results.

    sslscan provides comprehensive SSL/TLS posture analysis including:
    - Protocol versions (SSLv2/3, TLSv1.0-1.3)
    - Cipher suites and their security
    - Certificate details
    - Known vulnerabilities (Heartbleed, etc.)

    Example XML structure parsed:
    <ssltest host="..." port="443">
        <protocol type="tls" version="1.2" enabled="1" />
        <cipher status="preferred" sslversion="TLSv1.2" bits="256" cipher="ECDHE-RSA-AES256-GCM-SHA384" />
        <certificate>...</certificate>
    </ssltest>
    """
    __tablename__ = "sslscan_results"

    id = Column(String(36), primary_key=True)
    port_id = Column(String(36), ForeignKey("ports.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    tool_execution_id = Column(String(36), ForeignKey("tool_executions.id", ondelete="CASCADE"), nullable=True)

    # Protocol support (boolean flags)
    sslv2_enabled = Column(Boolean, default=False, nullable=False)
    sslv3_enabled = Column(Boolean, default=False, nullable=False)
    tlsv10_enabled = Column(Boolean, default=False, nullable=False)
    tlsv11_enabled = Column(Boolean, default=False, nullable=False)
    tlsv12_enabled = Column(Boolean, default=False, nullable=False)
    tlsv13_enabled = Column(Boolean, default=False, nullable=False)

    # Security features
    fallback_scsv_supported = Column(Boolean, nullable=True)  # TLS Fallback SCSV
    secure_renegotiation = Column(Boolean, nullable=True)
    compression_supported = Column(Boolean, nullable=True)

    # Vulnerability flags
    heartbleed_vulnerable = Column(Boolean, default=False, nullable=False)

    # Cipher suites (JSON arrays of cipher details)
    # Each cipher: {"status": "preferred/accepted", "sslversion": "TLSv1.2",
    #               "bits": 256, "cipher": "ECDHE-RSA-AES256-GCM-SHA384", "strength": "strong"}
    ciphers = Column(JSON, nullable=True)

    # Key exchange groups (JSON array)
    key_exchange_groups = Column(JSON, nullable=True)

    # Certificate information
    cert_subject = Column(String, nullable=True)  # Common Name or subject
    cert_issuer = Column(String, nullable=True)   # Certificate issuer
    cert_altnames = Column(Text, nullable=True)   # Subject Alternative Names
    cert_not_before = Column(String, nullable=True)  # Validity start
    cert_not_after = Column(String, nullable=True)   # Validity end
    cert_expired = Column(Boolean, nullable=True)
    cert_self_signed = Column(Boolean, nullable=True)
    cert_signature_algorithm = Column(String, nullable=True)  # e.g., "sha256WithRSAEncryption"
    cert_key_type = Column(String, nullable=True)   # RSA, EC, etc.
    cert_key_bits = Column(Integer, nullable=True)  # Key size in bits

    # Derived security findings (populated by analysis)
    # List of issues: [{"severity": "critical", "finding": "SSLv3 enabled", "detail": "..."}]
    findings = Column(JSON, nullable=True)

    # Overall grade (A, B, C, D, F based on findings)
    grade = Column(String(2), nullable=True)

    # Connection status
    connection_failed = Column(Boolean, default=False, nullable=False)
    failure_reason = Column(String, nullable=True)

    # Relationships
    port = relationship("Port", back_populates="sslscan_result")
    tool_execution = relationship("ToolExecution")
