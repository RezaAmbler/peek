from typing import List
from ..models import Vulnerability, ToolExecution, ScanTarget
from ..tools.nuclei import parse_nuclei_output
from sqlalchemy.orm import Session
import uuid

def create_vulnerabilities_from_nuclei(
    db: Session,
    tool_execution: ToolExecution,
    target: ScanTarget
) -> List[Vulnerability]:
    """
    Parse Nuclei raw output and create Vulnerability records.
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
        for vuln_data in vulns_data:
            # Check if vulnerability already exists (prevent duplicates)
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
                template_id=vuln_data['template_id'],
                name=vuln_data['name'],
                severity=vuln_data['severity'],
                vuln_type=vuln_data['type'],
                matched_at=vuln_data['matched_at'],
                host=vuln_data['host'],
                port=vuln_data['port'],
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
