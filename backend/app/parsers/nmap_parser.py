from typing import List
from ..models import Port, ToolExecution, ScanTarget
from ..tools.nmap import parse_nmap_xml
from sqlalchemy.orm import Session
import json
import uuid

def update_ports_from_nmap(
    db: Session,
    tool_execution: ToolExecution,
    target: ScanTarget
) -> List[Port]:
    """
    Parse nmap raw XML and update existing Port records with service info.
    """
    if not tool_execution.raw_output:
        return []

    try:
        # Parse raw XML
        ports_data = parse_nmap_xml(tool_execution.raw_output)

        # Store parsed output for debugging
        tool_execution.parsed_output = ports_data

        # Update existing Port records
        updated_ports = []
        for port_data in ports_data:
            # Find existing port record (created by masscan)
            port = db.query(Port).filter(
                Port.scan_target_id == str(target.id),
                Port.port == port_data['port'],
                Port.protocol == port_data['protocol']
            ).first()

            if port:
                # Update with service info from nmap
                port.service_name = port_data.get('service_name')
                port.product = port_data.get('product')
                port.version = port_data.get('version')
                port.state = port_data.get('state', port.state)

                if port_data.get('extra_info'):
                    port.extra_info = port_data['extra_info']

                # Update discovered_by to show nmap enhanced it
                port.discovered_by = 'nmap'
                port.tool_execution_id = str(tool_execution.id)

                updated_ports.append(port)
            else:
                # Port found by nmap but not by discovery phase
                # Only create new port records for OPEN ports
                # (filtered/closed ports are noise and shouldn't be stored)
                if port_data.get('state') == 'open':
                    new_port = Port(
                        id=str(uuid.uuid4()),
                        scan_target_id=str(target.id),
                        tool_execution_id=str(tool_execution.id),
                        port=port_data['port'],
                        protocol=port_data['protocol'],
                        state=port_data['state'],
                        service_name=port_data.get('service_name'),
                        product=port_data.get('product'),
                        version=port_data.get('version'),
                        extra_info=port_data.get('extra_info'),
                        discovered_by='nmap'
                    )
                    db.add(new_port)
                    updated_ports.append(new_port)

        db.flush()
        return updated_ports

    except Exception as e:
        tool_execution.error_message = f"Failed to parse nmap output: {str(e)}"
        db.flush()
        return []
