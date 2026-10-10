"""
Parser for Katana crawler output.

Creates DiscoveredEndpoint records from Katana's discovered URLs.
"""

from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
import uuid
import logging

from ..models import DiscoveredEndpoint, ToolExecution, ScanTarget, Port, Scan
from ..tools.katana import KatanaOutput, KatanaEndpoint, _parse_katana_output
from ..services.url_normalizer import normalize_url, compute_endpoint_hash

logger = logging.getLogger(__name__)


def create_endpoints_from_katana(
    db: Session,
    katana_output: KatanaOutput,
    scan: Scan,
    target: ScanTarget,
    port_rec: Optional[Port] = None,
    tool_execution: Optional[ToolExecution] = None,
) -> List[DiscoveredEndpoint]:
    """
    Create DiscoveredEndpoint records from Katana output.

    Handles deduplication via URL normalization and gracefully handles
    unique constraint violations (same endpoint discovered by multiple sources).

    Args:
        db: Database session
        katana_output: Parsed output from run_katana()
        scan: The Scan record
        target: The ScanTarget being crawled
        port_rec: Optional Port record to link endpoints to
        tool_execution: Optional ToolExecution record for traceability

    Returns:
        List of created DiscoveredEndpoint records
    """
    if not katana_output.endpoints:
        return []

    created_endpoints = []
    seen_normalized = set()  # Track seen URLs within this batch

    for katana_endpoint in katana_output.endpoints:
        try:
            endpoint = _create_endpoint_from_katana(
                db=db,
                katana_endpoint=katana_endpoint,
                scan=scan,
                target=target,
                port_rec=port_rec,
                tool_execution=tool_execution,
                seen_normalized=seen_normalized,
            )
            if endpoint:
                created_endpoints.append(endpoint)
        except IntegrityError:
            # Unique constraint violation - endpoint already exists
            db.rollback()
            logger.debug(f"Endpoint already exists: {katana_endpoint.url}")
            continue
        except Exception as e:
            logger.warning(f"Error creating endpoint for {katana_endpoint.url}: {e}")
            continue

    logger.info(f"Created {len(created_endpoints)} new endpoints from Katana crawl")
    return created_endpoints


def _create_endpoint_from_katana(
    db: Session,
    katana_endpoint: KatanaEndpoint,
    scan: Scan,
    target: ScanTarget,
    port_rec: Optional[Port],
    tool_execution: Optional[ToolExecution],
    seen_normalized: set,
) -> Optional[DiscoveredEndpoint]:
    """Create a single DiscoveredEndpoint from a KatanaEndpoint."""

    url = katana_endpoint.url
    method = katana_endpoint.method or "GET"

    # Normalize URL for deduplication
    normalized_url, components = normalize_url(url)

    # Create dedupe key (normalized URL + method)
    dedupe_key = (normalized_url, method)

    # Skip if already seen in this batch
    if dedupe_key in seen_normalized:
        return None
    seen_normalized.add(dedupe_key)

    # Check if already exists in database
    existing = db.query(DiscoveredEndpoint).filter(
        DiscoveredEndpoint.scan_id == str(scan.id),
        DiscoveredEndpoint.normalized_url == normalized_url,
        DiscoveredEndpoint.method == method
    ).first()

    if existing:
        return None

    # Compute content hash for cross-run comparison
    content_hash = compute_endpoint_hash(normalized_url, method)

    # Create endpoint record
    endpoint = DiscoveredEndpoint(
        id=str(uuid.uuid4()),
        scan_id=str(scan.id),
        scan_target_id=str(target.id),
        port_id=str(port_rec.id) if port_rec else None,
        tool_execution_id=str(tool_execution.id) if tool_execution else None,
        url=url,
        normalized_url=normalized_url,
        scheme=components['scheme'],
        host=components['host'],
        port=components['port'],
        path=components['path'],
        query=components['query'],
        method=method,
        status_code=katana_endpoint.status_code,
        content_type=katana_endpoint.content_type,
        content_length=katana_endpoint.content_length,
        depth=katana_endpoint.depth,
        source_tool='katana',
        content_hash=content_hash,
    )

    db.add(endpoint)
    db.flush()  # Get ID assigned

    return endpoint


def create_endpoints_from_raw_jsonl(
    db: Session,
    raw_output: str,
    scan: Scan,
    target: ScanTarget,
    port_rec: Optional[Port] = None,
    tool_execution: Optional[ToolExecution] = None,
) -> List[DiscoveredEndpoint]:
    """
    Create DiscoveredEndpoint records from raw Katana JSONL output.

    Alternative entry point when you have raw output instead of KatanaOutput.

    Args:
        db: Database session
        raw_output: Raw JSONL string from Katana
        scan: The Scan record
        target: The ScanTarget being crawled
        port_rec: Optional Port record
        tool_execution: Optional ToolExecution record

    Returns:
        List of created DiscoveredEndpoint records
    """
    if not raw_output or not raw_output.strip():
        return []

    # Parse JSONL with the runner's parser so both entry points read the same fields
    endpoints = _parse_katana_output(raw_output, max_endpoints=10**9)

    # Create KatanaOutput and use main function
    katana_output = KatanaOutput(
        success=True,
        endpoints=endpoints,
        raw_output=raw_output,
    )

    return create_endpoints_from_katana(
        db=db,
        katana_output=katana_output,
        scan=scan,
        target=target,
        port_rec=port_rec,
        tool_execution=tool_execution,
    )
