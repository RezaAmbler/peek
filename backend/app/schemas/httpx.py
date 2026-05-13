"""Pydantic schemas for httpx HTTP probing results."""
from pydantic import BaseModel
from typing import List, Optional


class HttpxResultResponse(BaseModel):
    """Response schema for httpx probe results."""
    id: str
    port_id: str
    ip_address: str
    port: int

    # HTTP Response
    status_code: Optional[int] = None
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    title: Optional[str] = None
    webserver: Optional[str] = None

    # Technology detection
    technologies: List[str] = []

    # Infrastructure
    cdn: Optional[str] = None
    waf: Optional[str] = None
    final_url: Optional[str] = None
    redirect_chain: List[str] = []

    # Metadata
    response_time_ms: Optional[int] = None

    # TLS info
    tls_version: Optional[str] = None
    jarm_hash: Optional[str] = None

    # Connection status
    connection_failed: bool = False
    failure_reason: Optional[str] = None

    class Config:
        from_attributes = True
