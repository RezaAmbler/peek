from typing import List
from ..models import Port, ToolExecution, ScanTarget
from ..tools.nmap import parse_nmap_discovery
from sqlalchemy.orm import Session
import uuid

def create_ports_from_nmap_discovery(
    db: Session,
    tool_execution: ToolExecution,
    target: ScanTarget
) -> List[Port]:
    """
    Parse nmap discovery raw output and create Port records.

    This is similar to create_ports_from_masscan but uses nmap discovery
    output format.
    """
    if not tool_execution.raw_output:
        return []

    try:
        # Parse raw XML
        ports_data = parse_nmap_discovery(tool_execution.raw_output)

        # Store parsed output for debugging
        tool_execution.parsed_output = ports_data

        # Create Port records
        created_ports = []
        for port_data in ports_data:
            # Check if port already exists (shouldn't, but defensive)
            existing = db.query(Port).filter(
                Port.scan_target_id == str(target.id),
                Port.port == port_data["port"],
                Port.protocol == port_data["protocol"]
            ).first()

            if existing:
                continue

            port = Port(
                id=str(uuid.uuid4()),
                scan_target_id=str(target.id),
                tool_execution_id=str(tool_execution.id),
                port=port_data["port"],
                protocol=port_data["protocol"],
                state=port_data["state"],
                discovered_by="nmap-discovery"
            )
            db.add(port)
            created_ports.append(port)

        db.flush()
        return created_ports

    except Exception as e:
        tool_execution.error_message = f"Failed to parse nmap discovery output: {str(e)}"
        db.flush()
        return []
