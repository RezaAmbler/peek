from typing import List, Optional
from ..models import Vulnerability, ToolExecution, ScanTarget, Port
from ..tools.nuclei import parse_nuclei_output
from ..services.fingerprint import finding_fingerprint
from sqlalchemy.orm import Session
import uuid

def create_vulnerabilities_from_nuclei(
    db: Session,
    tool_execution: ToolExecution,
    target: ScanTarget,
    port_rec: Optional[Port] = None,
    discovery_source: str = 'port'
) -> List[Vulnerability]:
    """
    Parse Nuclei raw output and create Vulnerability records.

    Args:
        db: Database session
        tool_execution: The ToolExecution record for this nuclei run
        target: The ScanTarget being scanned
        port_rec: Optional Port record to link vulnerabilities directly to the port
        discovery_source: 'port' for per-port scanning, 'endpoint' for URL list scanning
    """
    if not tool_execution.raw_output:
        return []

    try:
        # Parse raw JSONL
        vulns_data = parse_nuclei_output(tool_execution.raw_output)

        # Store parsed output for debugging
        tool_execution.parsed_output = str(vulns_data)

        # Create Vulnerability records
        created_vulns = []
        seen_keys = set()  # Track seen combinations within this batch
        for vuln_data in vulns_data:
            # Create a unique key for this vulnerability
            vuln_key = (
                vuln_data['template_id'],
                vuln_data['port'],
                vuln_data['matched_at']
            )

            # Skip if we've already seen this combination in this batch
            if vuln_key in seen_keys:
                continue
            seen_keys.add(vuln_key)

            # Check if vulnerability already exists in database (prevent duplicates)
            existing = db.query(Vulnerability).filter(
                Vulnerability.scan_target_id == str(target.id),
                Vulnerability.template_id == vuln_data['template_id'],
                Vulnerability.port == vuln_data['port'],
                Vulnerability.matched_at == vuln_data['matched_at']
            ).first()

            if existing:
                continue

            vuln = Vulnerability(
                id=str(uuid.uuid4()),
                scan_target_id=str(target.id),
                tool_execution_id=str(tool_execution.id),
                port_id=str(port_rec.id) if port_rec else None,
                template_id=vuln_data['template_id'],
                name=vuln_data['name'],
                severity=vuln_data['severity'],
                vuln_type=vuln_data['type'],
                source_tool='nuclei',  # Identify findings from nuclei scanner
                matched_at=vuln_data['matched_at'],
                host=vuln_data['host'],
                port=vuln_data['port'],
                fingerprint=finding_fingerprint(
                    host=vuln_data['host'],
                    template_id=vuln_data['template_id'],
                    port=vuln_data['port'],
                    matched_at=vuln_data['matched_at'],
                ),
                discovery_source=discovery_source,  # 'port' or 'endpoint'
                extracted_results=vuln_data.get('extracted_results'),
                curl_command=vuln_data.get('curl_command'),
                description=vuln_data.get('description'),
                reference=vuln_data.get('reference'),
                tags=vuln_data.get('tags')
            )
            db.add(vuln)
            created_vulns.append(vuln)

        db.flush()
        return created_vulns

    except Exception as e:
        tool_execution.error_message = f"Failed to parse Nuclei output: {str(e)}"
        db.flush()
        return []
