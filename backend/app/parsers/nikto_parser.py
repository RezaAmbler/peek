"""Parser for Nikto scan results."""
import logging
import uuid
from typing import List, Optional
from sqlalchemy.orm import Session

from ..models.vulnerability import Vulnerability
from ..models.tool_execution import ToolExecution
from ..models.scan_target import ScanTarget
from ..models.port import Port
from ..tools.nikto import parse_nikto_output, map_nikto_severity

logger = logging.getLogger(__name__)


def create_vulnerabilities_from_nikto(
    db: Session,
    tool_execution: ToolExecution,
    target: ScanTarget,
    port_rec: Optional[Port] = None,
    host: str = "",
    port: int = 80
) -> List[Vulnerability]:
    """
    Create Vulnerability records from Nikto output.

    Args:
        db: Database session
        tool_execution: Associated ToolExecution record
        target: ScanTarget being scanned
        port_rec: Optional Port record
        host: Target host/IP
        port: Target port

    Returns:
        List of created Vulnerability records
    """
    raw_output = tool_execution.raw_output
    if not raw_output:
        logger.warning("No Nikto output to parse")
        return []

    findings = parse_nikto_output(raw_output)
    logger.info(f"Parsing {len(findings)} Nikto findings for {host}:{port}")

    vulnerabilities = []
    seen = set()  # Dedupe within batch

    for finding in findings:
        # Create dedup key
        finding_id = finding.get('id', 'unknown')
        finding_url = finding.get('url', '/')
        finding_name = finding.get('name', '')
        dedup_key = (finding_id, finding_url, port)

        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        # Skip findings without valid name or ID - these are parser failures
        if finding_id == 'unknown' and (not finding_name or 'unknown' in finding_name.lower()):
            logger.debug(f"Skipping nikto finding with unknown name/id: {finding}")
            continue

        # Map severity
        severity = map_nikto_severity(finding)

        # Build matched_at URL
        protocol = "https" if port == 443 else "http"
        url_path = finding_url if finding_url.startswith('/') else f"/{finding_url}"
        matched_at = f"{protocol}://{host}:{port}{url_path}"

        # Check for existing duplicate in DB (all 4 unique constraint columns)
        existing = db.query(Vulnerability).filter(
            Vulnerability.scan_target_id == str(target.id),
            Vulnerability.template_id == f"nikto-{finding_id}",
            Vulnerability.port == port,
            Vulnerability.matched_at == matched_at
        ).first()

        if existing:
            logger.debug(f"Skipping duplicate Nikto finding: {finding_id} at {matched_at}")
            continue

        # Create vulnerability record
        vuln = Vulnerability(
            id=str(uuid.uuid4()),
            scan_target_id=str(target.id),
            tool_execution_id=str(tool_execution.id),
            port_id=str(port_rec.id) if port_rec else None,
            template_id=f"nikto-{finding_id}",
            name=finding.get('name', 'Unknown Nikto Finding')[:500],  # Truncate long names
            severity=severity,
            vuln_type="misconfiguration",
            matched_at=matched_at,
            host=host,
            port=port,
            source_tool="nikto",
            description=finding.get('description', '')[:2000] if finding.get('description') else None,
            reference=[f"OSVDB-{finding.get('osvdb')}"] if finding.get('osvdb') else [],
            tags=["nikto", "web", severity],
            extracted_results={
                "method": finding.get('method', 'GET'),
                "osvdb": finding.get('osvdb', ''),
                "nikto_id": finding_id,
            }
        )

        db.add(vuln)
        vulnerabilities.append(vuln)

    if vulnerabilities:
        logger.info(f"Created {len(vulnerabilities)} Nikto vulnerabilities for {host}:{port}")

    return vulnerabilities
