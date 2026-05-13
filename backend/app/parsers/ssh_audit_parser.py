from typing import Optional
from ..models import SSHAudit, Port, ToolExecution
from ..tools.ssh_audit import parse_ssh_audit_output
from sqlalchemy.orm import Session
import uuid

def create_ssh_audit_from_output(
    db: Session,
    tool_execution: ToolExecution,
    port: Port
) -> Optional[SSHAudit]:
    """
    Parse ssh-audit raw output and create SSHAudit record.
    """
    if not tool_execution.raw_output:
        return None

    try:
        # Parse raw JSON
        audit_data = parse_ssh_audit_output(tool_execution.raw_output)

        # Store parsed output for debugging
        tool_execution.parsed_output = audit_data

        # Check if audit already exists (shouldn't, but defensive)
        existing = db.query(SSHAudit).filter(
            SSHAudit.port_id == str(port.id)
        ).first()

        if existing:
            # Update existing
            audit = existing
        else:
            # Create new
            audit = SSHAudit(
                id=str(uuid.uuid4()),
                port_id=str(port.id),
                tool_execution_id=str(tool_execution.id)
            )
            db.add(audit)

        # Populate fields
        audit.banner = audit_data.get("banner")
        audit.ssh_version = audit_data.get("ssh_version")
        audit.key_exchange_algorithms = audit_data.get("key_exchange")
        audit.host_key_algorithms = audit_data.get("host_keys")
        audit.encryption_algorithms = audit_data.get("encryption")
        audit.mac_algorithms = audit_data.get("mac")
        audit.compression_algorithms = audit_data.get("compression")
        audit.vulnerabilities = audit_data.get("vulnerabilities")
        audit.recommendations = audit_data.get("recommendations")
        audit.connection_failed = False

        db.flush()
        return audit

    except Exception as e:
        # Log parse error but don't fail the scan
        tool_execution.error_message = f"Failed to parse ssh-audit output: {str(e)}"

        # Create minimal audit record to track the failure
        audit = SSHAudit(
            id=str(uuid.uuid4()),
            port_id=str(port.id),
            tool_execution_id=str(tool_execution.id),
            connection_failed=True,
            failure_reason=str(e)
        )
        db.add(audit)
        db.flush()
        return audit
