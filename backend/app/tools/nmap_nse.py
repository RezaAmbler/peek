"""
Nmap NSE (Nmap Scripting Engine) tool wrapper.

Runs targeted NSE scripts against specific ports based on service profiles.
This is separate from the main nmap service detection to allow focused,
per-service security analysis.
"""
import os
import re
import xml.etree.ElementTree as ET
from typing import List, Dict
from ..core.config import settings
from ..core.validators import validate_target, validate_port, ValidationError
from .base import ToolResult, failure_reason, read_output, run_command, temp_workdir


# NSE script names / categories / globs, with an optional directory prefix
_SCRIPT_NAME_RE = re.compile(r'^[A-Za-z0-9_.*/-]+$')


def _validate_scripts(scripts) -> None:
    for script in scripts:
        if not isinstance(script, str) or not _SCRIPT_NAME_RE.match(script):
            raise ValidationError(f"invalid NSE script name: {script!r}")


def _execute_nse(cmd: List[str], output_path, timeout: int, label: str) -> ToolResult:
    """Run nmap writing XML to ``output_path``; non-zero exit is never a success."""
    run = run_command(cmd, timeout=timeout)
    raw_xml = read_output(output_path)

    error = failure_reason(label, run, timeout)
    if error:
        return ToolResult.from_command(False, raw_xml if raw_xml.strip() else "", error, run)

    if not raw_xml.strip():
        return ToolResult.from_command(
            False, "", f"{label} produced empty output: {run.diagnostics()}", run)

    return ToolResult.from_command(True, raw_xml, None, run)


def run_nmap_nse(
    ip: str,
    port: int,
    scripts: List[str],
    protocol: str = "tcp",
    timeout: int = 300
) -> ToolResult:
    """
    Execute nmap with specific NSE scripts against a single port.

    Args:
        ip: Target IP address
        port: Port number to scan
        scripts: List of NSE scripts to run (e.g., ["rdp-enum-encryption", "rdp-ntlm-info"])
        protocol: "tcp" or "udp"
        timeout: Max execution time in seconds

    Returns:
        ToolResult, unpackable as (success: bool, raw_xml: str, error: Optional[str])
    """
    if not scripts:
        return ToolResult(True, "", None)

    # Validate inputs to prevent command/argument injection
    try:
        ip = validate_target(ip)
        port = validate_port(port)
        _validate_scripts(scripts)
    except ValidationError as e:
        return ToolResult(False, "", f"Input validation failed: {e}")

    with temp_workdir('nmap_nse_') as workdir:
        output_path = workdir / 'nse.xml'

        # Build script string: "script1,script2,script3"
        script_string = ','.join(scripts)

        if protocol == "udp":
            scan_type = '-sU'  # needs raw sockets
            privilege = ['--privileged'] if os.geteuid() != 0 else []
        else:
            scan_type = '-sT'  # TCP connect scan for Docker compatibility
            privilege = []

        cmd = [
            settings.NMAP_PATH or 'nmap',
            *privilege,
            scan_type,
            '-Pn',                    # Skip host discovery
            '-sV',                    # Service version detection (helps scripts)
            f'-p{port}',              # Single port
            f'--script={script_string}',  # NSE scripts
            '-oX', str(output_path),  # XML output
            ip,
        ]

        return _execute_nse(cmd, output_path, timeout, "Nmap NSE")


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
            if ports_section is None:
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
) -> ToolResult:
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
        return ToolResult(True, "", None)

    # Collect all unique scripts and ports
    all_scripts = set()
    tcp_ports = set()
    udp_ports = set()

    try:
        ip = validate_target(ip)
        for ps in ports_scripts:
            all_scripts.update(ps.get('scripts', []))
            port = validate_port(ps['port'])
            if ps.get('protocol', 'tcp') == 'udp':
                udp_ports.add(port)
            else:
                tcp_ports.add(port)
        _validate_scripts(all_scripts)
    except (ValidationError, KeyError) as e:
        return ToolResult(False, "", f"Input validation failed: {e}")

    if not all_scripts:
        return ToolResult(True, "", None)

    with temp_workdir('nmap_nse_') as workdir:
        output_path = workdir / 'nse.xml'

        cmd = [settings.NMAP_PATH or 'nmap']
        if udp_ports and os.geteuid() != 0:
            cmd.append('--privileged')  # -sU needs raw sockets (file capability)
        cmd.extend([
            '-Pn',
            '-sV',
            f'--script={",".join(sorted(all_scripts))}',
            '-oX', str(output_path),
        ])

        # Handle mixed TCP/UDP scanning
        tcp_spec = ','.join(str(p) for p in sorted(tcp_ports))
        udp_spec = ','.join(str(p) for p in sorted(udp_ports))
        if tcp_ports and udp_ports:
            cmd.extend(['-sT', '-sU', '-p', f'T:{tcp_spec},U:{udp_spec}'])
        elif udp_ports:
            cmd.extend(['-sU', '-p', udp_spec])
        else:
            cmd.extend(['-sT', '-p', tcp_spec])

        cmd.append(ip)

        return _execute_nse(cmd, output_path, timeout, "Nmap NSE batch")
