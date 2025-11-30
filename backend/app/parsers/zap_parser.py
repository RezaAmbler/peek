"""Parser for ZAP scan results."""
import logging
import uuid
from typing import List, Optional
from sqlalchemy.orm import Session

from ..models.vulnerability import Vulnerability
from ..models.tool_execution import ToolExecution
from ..models.scan_target import ScanTarget
from ..models.port import Port
from ..tools.zap import parse_zap_alerts

logger = logging.getLogger(__name__)


def create_vulnerabilities_from_zap(
    db: Session,
    tool_execution: ToolExecution,
    target: ScanTarget,
    port_rec: Optional[Port] = None,
    host: str = "",
    port: int = 80
) -> List[Vulnerability]:
    """
    Create Vulnerability records from ZAP output.

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
        logger.warning("No ZAP output to parse")
        return []

    findings = parse_zap_alerts(raw_output)
    logger.info(f"Parsing {len(findings)} ZAP findings for {host}:{port}")

    vulnerabilities = []
    seen = set()  # Dedupe within batch

    for finding in findings:
        # Create dedup key matching the unique constraint:
        # (scan_target_id, template_id, port, matched_at)
        alert_id = finding.get('alert_id', 'unknown')
        finding_url = finding.get('url', '')

        # Use the URL from the finding if available, otherwise construct it
        matched_at = finding_url if finding_url else f"http://{host}:{port}/"

        # Dedup key must match the DB unique constraint columns
        template_id = f"zap-{alert_id}"
        dedup_key = (template_id, port, matched_at)

        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        # Check for existing duplicate in DB (all 4 constraint columns)
        existing = db.query(Vulnerability).filter(
            Vulnerability.scan_target_id == str(target.id),
            Vulnerability.template_id == template_id,
            Vulnerability.port == port,
            Vulnerability.matched_at == matched_at
        ).first()

        if existing:
            logger.debug(f"Skipping duplicate ZAP finding: {alert_id} at {matched_at}")
            continue

        # Create vulnerability record
        vuln = Vulnerability(
            id=str(uuid.uuid4()),
            scan_target_id=str(target.id),
            tool_execution_id=str(tool_execution.id),
            port_id=str(port_rec.id) if port_rec else None,
            template_id=template_id,
            name=finding.get('name', 'Unknown ZAP Finding')[:500],
            severity=finding.get('severity', 'info'),
            vuln_type="web",
            matched_at=matched_at,
            host=host,
            port=port,
            source_tool="zap",
            description=finding.get('description', '')[:2000] if finding.get('description') else None,
            extracted_results={
                "method": finding.get('method', 'GET'),
                "param": finding.get('param', ''),
                "attack": finding.get('attack', ''),
                "evidence": finding.get('evidence', '')[:500] if finding.get('evidence') else '',
                "solution": finding.get('solution', ''),
                "confidence": finding.get('confidence', ''),
                "cwe": finding.get('cwe', ''),
                "wasc": finding.get('wasc', ''),
            },
            reference=[finding.get('reference', '')] if finding.get('reference') else [],
            tags=["zap", "web", f"cwe-{finding.get('cwe', 'unknown')}"] if finding.get('cwe') else ["zap", "web"],
        )

        db.add(vuln)
        vulnerabilities.append(vuln)

    if vulnerabilities:
        logger.info(f"Created {len(vulnerabilities)} ZAP vulnerabilities for {host}:{port}")

    return vulnerabilities
