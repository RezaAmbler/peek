"""
TestsslResult model for deep TLS/SSL analysis with testssl.sh.

testssl.sh provides comprehensive TLS posture analysis including:
- Protocol versions (SSLv2/3, TLSv1.0-1.3)
- Cipher suites with security ratings
- Certificate details and chain validation
- Known vulnerabilities (BEAST, POODLE, Heartbleed, DROWN, ROBOT, etc.)
- Forward secrecy evaluation
- Server configuration issues
"""

from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, JSON, Text, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from ..database import Base
from ..core.timeutil import utcnow


class TestsslResult(Base):
    """
    Stores testssl.sh deep TLS/SSL analysis results.

    testssl.sh JSON output structure (simplified):
    {
        "scanResult": [{
            "protocols": [...],
            "vulnerabilities": [...],
            "ciphers": [...],
            "serverDefaults": [...],
            "cipher_tests": [...]
        }]
    }
    """
    __tablename__ = "testssl_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Relationships - linked to scan, target, port, and tool execution
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_target_id = Column(String(36), ForeignKey("scan_targets.id", ondelete="CASCADE"), nullable=False, index=True)
    port_id = Column(String(36), ForeignKey("ports.id", ondelete="CASCADE"), nullable=False, index=True)
    tool_execution_id = Column(String(36), ForeignKey("tool_executions.id", ondelete="CASCADE"), nullable=True)

    # Target info
    host = Column(String, nullable=False)
    port = Column(Integer, nullable=False)

    # Connection status
    connection_failed = Column(Boolean, default=False, nullable=False)
    failure_reason = Column(String, nullable=True)

    # Protocol support (JSON dict for flexibility)
    # {"SSLv2": false, "SSLv3": false, "TLS1.0": true, "TLS1.1": true, "TLS1.2": true, "TLS1.3": true}
    protocols = Column(JSON, nullable=True)

    # Certificate information (JSON dict)
    # {
    #   "subject": "CN=example.com",
    #   "issuer": "CN=Let's Encrypt",
    #   "notBefore": "2024-01-01",
    #   "notAfter": "2024-04-01",
    #   "daysUntilExpiry": 90,
    #   "keySize": 2048,
    #   "signatureAlgorithm": "SHA256withRSA",
    #   "serialNumber": "...",
    #   "fingerprint": "...",
    #   "selfSigned": false,
    #   "expired": false,
    #   "chainIssues": [],
    #   "ocspStapling": true,
    #   "mustStaple": false,
    #   "scts": true
    # }
    certificate_info = Column(JSON, nullable=True)

    # Vulnerabilities (JSON list of findings)
    # [
    #   {"id": "heartbleed", "severity": "critical", "vulnerable": true, "detail": "..."},
    #   {"id": "poodle_ssl", "severity": "high", "vulnerable": false, "detail": "..."},
    #   {"id": "beast", "severity": "medium", "vulnerable": true, "detail": "..."},
    #   ...
    # ]
    vulnerabilities = Column(JSON, nullable=True)

    # Cipher findings (JSON dict)
    # {
    #   "weak": [{"name": "DES-CBC3-SHA", "bits": 168, "grade": "C"}],
    #   "preferred": [{"name": "TLS_AES_256_GCM_SHA384", "bits": 256, "grade": "A"}],
    #   "forwardSecrecy": true,
    #   "aead": true,
    #   "nullCiphers": false,
    #   "exportCiphers": false,
    #   "rc4": false
    # }
    cipher_findings = Column(JSON, nullable=True)

    # Server configuration issues (JSON list)
    # [
    #   {"id": "secure_renegotiation", "status": "ok"},
    #   {"id": "compression", "status": "vulnerable", "detail": "CRIME"},
    #   {"id": "fallback_scsv", "status": "ok"},
    #   ...
    # ]
    server_config = Column(JSON, nullable=True)

    # Overall grade (A+, A, B, C, D, F)
    overall_grade = Column(String(2), nullable=True)

    # Raw artifact path (full JSON output file)
    artifact_path = Column(String, nullable=True)

    # Timing
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    scan = relationship("Scan", backref="testssl_results")
    scan_target = relationship("ScanTarget", backref="testssl_results")
    port_rel = relationship("Port", backref="testssl_result")
    tool_execution = relationship("ToolExecution")

    def __repr__(self):
        return f"<TestsslResult {self.host}:{self.port} grade={self.overall_grade}>"
