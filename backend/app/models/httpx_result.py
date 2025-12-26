"""
Stores httpx HTTP probing results.

httpx provides fast HTTP probing with technology fingerprinting:
- HTTP response metadata (status, title, headers)
- Technology detection via Wappalyzer fingerprints
- CDN/WAF detection
- TLS information and JARM fingerprinting
- Redirect chain tracking
"""
from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, JSON
from sqlalchemy.orm import relationship
from ..database import Base


class HttpxResult(Base):
    """
    Stores httpx HTTP probe results for a port.

    Example httpx JSON output parsed:
    {
        "url": "https://example.com:8443",
        "status_code": 200,
        "title": "Example Site",
        "webserver": "nginx/1.18.0",
        "tech": ["nginx", "WordPress", "PHP"],
        "cdn": "cloudflare",
        "jarm": "..."
    }
    """
    __tablename__ = "httpx_results"

    id = Column(String(36), primary_key=True)
    port_id = Column(String(36), ForeignKey("ports.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    tool_execution_id = Column(String(36), ForeignKey("tool_executions.id", ondelete="CASCADE"), nullable=True)

    # HTTP Response
    status_code = Column(Integer, nullable=True)
    content_length = Column(Integer, nullable=True)
    content_type = Column(String, nullable=True)
    title = Column(String, nullable=True)
    webserver = Column(String, nullable=True)
    method = Column(String, nullable=True)  # GET, POST, etc.

    # Technology Fingerprinting (from Wappalyzer-style detection)
    # Array of detected technologies: ["WordPress", "PHP", "nginx"]
    technologies = Column(JSON, nullable=True)

    # Infrastructure Detection
    cdn = Column(String, nullable=True)  # "cloudflare", "akamai", etc.
    waf = Column(String, nullable=True)  # Detected WAF

    # Redirect tracking
    # Array of URLs in redirect chain: ["http://example.com", "https://www.example.com/"]
    redirect_chain = Column(JSON, nullable=True)
    final_url = Column(String, nullable=True)

    # Response Metadata
    response_time_ms = Column(Integer, nullable=True)
    body_hash = Column(String, nullable=True)  # MD5 hash for content comparison

    # TLS Information
    tls_version = Column(String, nullable=True)  # "TLS 1.3", etc.
    tls_cipher = Column(String, nullable=True)
    jarm_hash = Column(String, nullable=True)  # JARM TLS fingerprint

    # Virtual Hosts (if vhost detection enabled)
    virtual_hosts = Column(JSON, nullable=True)

    # Connection Status
    connection_failed = Column(Boolean, default=False, nullable=False)
    failure_reason = Column(String, nullable=True)

    # Relationships
    port_record = relationship("Port", back_populates="httpx_results")
    tool_execution = relationship("ToolExecution")
