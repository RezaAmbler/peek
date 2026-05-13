"""
Port Classification Utilities for HTTP and TLS Services

Provides centralized logic for identifying HTTP and TLS-capable ports,
eliminating duplication across httpx, nikto, zap, katana, and testssl phases.
"""

from typing import List, Optional, TYPE_CHECKING
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from ..models.port import Port
    from ..models.scan_target import ScanTarget

# HTTP service names recognized by nmap
HTTP_SERVICES = frozenset([
    'http',
    'https',
    'ssl/http',
    'http-proxy',
    'http-alt',
])

# Common HTTP ports that may not be identified by service name
HTTP_PORT_NUMBERS = frozenset([
    80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000,
    8001, 8008, 8081, 8082, 8180, 8280, 8880, 9080, 9443,
])

# TLS/SSL ports (re-exported from service_profile for consistency)
# Import at function level to avoid circular imports
def get_ssl_ports():
    """Get set of well-known SSL/TLS ports."""
    from .service_profile import SSL_PORTS
    return SSL_PORTS


def get_http_candidate_ports(
    db: Session,
    scan_id: str,
    target_id: Optional[str] = None,
    include_port_fallback: bool = True
) -> List["Port"]:
    """
    Get HTTP candidate ports for a scan or specific target.

    Args:
        db: Database session
        scan_id: Scan ID to query
        target_id: Optional target ID to filter (if None, queries all targets)
        include_port_fallback: If True, also match by common HTTP port numbers
                              even if service name is unknown

    Returns:
        List of Port records that are HTTP candidates
    """
    from ..models.port import Port
    from ..models.scan_target import ScanTarget

    query = db.query(Port).join(ScanTarget).filter(
        ScanTarget.scan_id == str(scan_id),
        Port.state == 'open'
    )

    if target_id:
        query = query.filter(Port.scan_target_id == str(target_id))

    if include_port_fallback:
        # Match by service name OR port number
        query = query.filter(
            (Port.service_name.in_(HTTP_SERVICES)) |
            (Port.port.in_(HTTP_PORT_NUMBERS))
        )
    else:
        # Match by service name only
        query = query.filter(Port.service_name.in_(HTTP_SERVICES))

    return query.all()


def get_tls_candidate_ports(
    db: Session,
    scan_id: str,
    target_id: Optional[str] = None,
    require_ssl_service: bool = False
) -> List["Port"]:
    """
    Get TLS/SSL candidate ports for testssl.sh scanning.

    Args:
        db: Database session
        scan_id: Scan ID to query
        target_id: Optional target ID to filter
        require_ssl_service: If True, only return ports with ssl/* service name.
                            If False (default), also include well-known SSL ports.

    Returns:
        List of Port records that are TLS candidates
    """
    from ..models.port import Port
    from ..models.scan_target import ScanTarget

    ssl_ports = get_ssl_ports()

    query = db.query(Port).join(ScanTarget).filter(
        ScanTarget.scan_id == str(scan_id),
        Port.state == 'open'
    )

    if target_id:
        query = query.filter(Port.scan_target_id == str(target_id))

    if require_ssl_service:
        # Only ssl/* services
        query = query.filter(Port.service_name.like('ssl/%'))
    else:
        # ssl/* service OR well-known SSL port OR httpx detected TLS
        # Note: httpx_results check handled at caller level for efficiency
        query = query.filter(
            (Port.service_name.like('ssl/%')) |
            (Port.port.in_(ssl_ports))
        )

    return query.all()


def is_http_service(service_name: Optional[str], port_number: int) -> bool:
    """
    Check if a port appears to be an HTTP service.

    Args:
        service_name: Nmap service name (may be None)
        port_number: Port number

    Returns:
        True if the port is likely an HTTP service
    """
    if service_name and service_name.lower() in HTTP_SERVICES:
        return True
    return port_number in HTTP_PORT_NUMBERS


def is_tls_capable(
    service_name: Optional[str],
    port_number: int,
    httpx_tls_version: Optional[str] = None
) -> bool:
    """
    Check if a port appears to support TLS/SSL.

    Args:
        service_name: Nmap service name (may be None)
        port_number: Port number
        httpx_tls_version: TLS version from httpx probe (if available)

    Returns:
        True if the port is likely TLS-capable
    """
    # httpx TLS detection is most reliable
    if httpx_tls_version:
        return True

    # Nmap ssl/* service detection
    if service_name and service_name.lower().startswith('ssl/'):
        return True

    # Well-known SSL ports
    ssl_ports = get_ssl_ports()
    return port_number in ssl_ports
