"""
Nmap NSE (Nmap Scripting Engine) tool wrapper.

Runs targeted NSE scripts against specific ports based on service profiles.
This is separate from the main nmap service detection to allow focused,
per-service security analysis.
"""
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Tuple, List, Optional, Dict
from ..core.config import settings


def run_nmap_nse(
    ip: str,
    port: int,
    scripts: List[str],
    protocol: str = "tcp",
    timeout: int = 300
) -> Tuple[bool, str, Optional[str]]:
    """
    Execute nmap with specific NSE scripts against a single port.

    Args:
        ip: Target IP address
        port: Port number to scan
        scripts: List of NSE scripts to run (e.g., ["rdp-enum-encryption", "rdp-ntlm-info"])
        protocol: "tcp" or "udp"
        timeout: Max execution time in seconds

    Returns:
        (success: bool, raw_xml: str, error: Optional[str])
    """
    if not scripts:
        return True, "", None

    # Create temp file for XML output
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        output_path = Path(f.name)

    try:
        # Build script string: "script1,script2,script3"
        script_string = ','.join(scripts)

        # Build command
        cmd = [
            settings.NMAP_PATH or 'nmap',
            '-Pn',                    # Skip host discovery
            '-sV',                    # Service version detection (helps scripts)
            f'-p{port}',              # Single port
            f'--script={script_string}',  # NSE scripts
            '-oX', str(output_path),  # XML output
        ]

        # Add UDP flag if needed
        if protocol == "udp":
            cmd.insert(1, '-sU')
        else:
            cmd.insert(1, '-sT')  # TCP connect scan for Docker compatibility

        cmd.append(ip)

        # Execute
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Check if output file exists
        if not output_path.exists():
            return False, "", f"Nmap NSE did not create output file. stderr: {result.stderr}"

        # Read raw XML output
        raw_xml = output_path.read_text()

        if not raw_xml.strip():
            return False, "", "Nmap NSE produced empty output"

        return True, raw_xml, None

    except subprocess.TimeoutExpired:
        return False, "", f"Nmap NSE timed out after {timeout} seconds"
    except Exception as e:
        return False, "", f"Nmap NSE execution failed: {str(e)}"
    finally:
        # Cleanup temp file
        if output_path.exists():
            output_path.unlink()


def parse_nse_output(raw_xml: str) -> List[Dict]:
    """
    Parse NSE script results from nmap XML output.

    Returns list of script findings:
    [
        {
            "port": 3389,
            "protocol": "tcp",
            "script_id": "rdp-enum-encryption",
            "output": "Security layer\\n  CredSSP (NLA): SUCCESS",
            "elements": {"Security layer": "CredSSP (NLA): SUCCESS", ...}
        }
    ]

    NSE XML structure:
    <port protocol="tcp" portid="3389">
        <script id="rdp-enum-encryption" output="...">
            <elem key="Security layer">CredSSP (NLA): SUCCESS</elem>
            <table key="RDP Encryption level">
                <elem>High</elem>
            </table>
        </script>
    </port>
    """
    try:
        root = ET.fromstring(raw_xml)
        findings = []

        for host in root.findall('host'):
            ports_section = host.find('ports')
            if not ports_section:
                continue

            for port_elem in ports_section.findall('port'):
                port_id = int(port_elem.get('portid'))
                protocol = port_elem.get('protocol', 'tcp')

                # Find all script elements
                for script in port_elem.findall('script'):
                    script_id = script.get('id')
                    raw_output = script.get('output', '')

                    # Parse <elem> children into key-value pairs
                    elements = _parse_script_elements(script)

                    findings.append({
                        'port': port_id,
                        'protocol': protocol,
                        'script_id': script_id,
                        'output': raw_output,
                        'elements': elements
                    })

        return findings

    except ET.ParseError as e:
        raise ValueError(f"Invalid XML from nmap NSE: {str(e)}")


def _parse_script_elements(script_elem) -> Dict:
    """
    Parse <elem> and <table> children from a script element.

    Handles nested structures:
    - <elem key="name">value</elem> -> {"name": "value"}
    - <elem>value</elem> -> {"_default": "value"}
    - <table key="name"><elem>v1</elem><elem>v2</elem></table> -> {"name": ["v1", "v2"]}
    """
    elements = {}

    for child in script_elem:
        if child.tag == 'elem':
            key = child.get('key', '_default')
            value = child.text or ''
            elements[key] = value.strip()

        elif child.tag == 'table':
            key = child.get('key', '_table')
            # Table contains a list of values
            values = []
            for elem in child.findall('elem'):
                elem_key = elem.get('key')
                if elem_key:
                    # Named element in table
                    if key not in elements or not isinstance(elements.get(key), dict):
                        elements[key] = {}
                    elements[key][elem_key] = (elem.text or '').strip()
                else:
                    values.append((elem.text or '').strip())

            if values:
                elements[key] = values

    return elements


def determine_nse_severity(script_id: str, output: str, elements: Dict) -> str:
    """
    Determine severity based on script ID and output content.

    This is a heuristic mapping that can be customized.
    Returns: "critical", "high", "medium", "low", or "info"
    """
    output_lower = output.lower()
    script_lower = script_id.lower()

    # Critical findings
    if 'monlist' in script_lower and 'vulnerable' in output_lower:
        return 'critical'  # NTP monlist amplification
    if 'anonymous' in output_lower and 'allowed' in output_lower:
        return 'critical'  # Anonymous access allowed
    if 'heartbleed' in script_lower and 'vulnerable' in output_lower:
        return 'critical'

    # High findings
    if 'no encryption' in output_lower or 'none' in output_lower:
        if 'encryption' in script_lower:
            return 'high'  # No encryption on RDP/etc
    if 'recursion' in script_lower and 'enabled' in output_lower:
        return 'high'  # DNS recursion enabled
    if 'vrfy' in output_lower or 'expn' in output_lower:
        return 'medium'  # SMTP user enumeration

    # Medium findings
    if 'weak' in output_lower:
        return 'medium'

    # Low findings (informational but noteworthy)
    if 'ntlm' in script_lower and elements:
        return 'low'  # NTLM info disclosure

    # Default to info
    return 'info'


def run_nmap_nse_batch(
    ip: str,
    ports_scripts: List[Dict],
    timeout: int = 600
) -> Tuple[bool, str, Optional[str]]:
    """
    Run NSE scripts on multiple ports in a single nmap invocation.

    Args:
        ip: Target IP address
        ports_scripts: List of {"port": int, "protocol": str, "scripts": [str]}
        timeout: Max execution time in seconds

    This is more efficient than running separate scans per port,
    but all ports share the same script set.
    """
    if not ports_scripts:
        return True, "", None

    # Collect all unique scripts and ports
    all_scripts = set()
    tcp_ports = set()
    udp_ports = set()

    for ps in ports_scripts:
        all_scripts.update(ps.get('scripts', []))
        if ps.get('protocol', 'tcp') == 'udp':
            udp_ports.add(ps['port'])
        else:
            tcp_ports.add(ps['port'])

    if not all_scripts:
        return True, "", None

    # Create temp file for XML output
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        output_path = Path(f.name)

    try:
        # Build command
        cmd = [
            settings.NMAP_PATH or 'nmap',
            '-Pn',
            '-sV',
            f'--script={",".join(all_scripts)}',
            '-oX', str(output_path),
        ]

        # Handle mixed TCP/UDP scanning
        if tcp_ports and udp_ports:
            cmd.extend(['-sT', '-sU'])
            port_spec = f'T:{",".join(str(p) for p in tcp_ports)},U:{",".join(str(p) for p in udp_ports)}'
            cmd.extend(['-p', port_spec])
        elif udp_ports:
            cmd.append('-sU')
            cmd.extend(['-p', ','.join(str(p) for p in udp_ports)])
        else:
            cmd.append('-sT')
            cmd.extend(['-p', ','.join(str(p) for p in tcp_ports)])

        cmd.append(ip)

        # Execute
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if not output_path.exists():
            return False, "", f"Nmap NSE batch did not create output file. stderr: {result.stderr}"

        raw_xml = output_path.read_text()

        if not raw_xml.strip():
            return False, "", "Nmap NSE batch produced empty output"

        return True, raw_xml, None

    except subprocess.TimeoutExpired:
        return False, "", f"Nmap NSE batch timed out after {timeout} seconds"
    except Exception as e:
        return False, "", f"Nmap NSE batch execution failed: {str(e)}"
    finally:
        if output_path.exists():
            output_path.unlink()
