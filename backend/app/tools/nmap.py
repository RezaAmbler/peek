import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Tuple, List, Optional, Dict
from ..core.config import settings

def run_nmap(
    ip: str,
    ports: List[int],
    nmap_args: List[str],
    timeout: int = 600
) -> Tuple[bool, str, Optional[str]]:
    """
    Execute nmap for service detection on specific ports.

    Args:
        ip: Target IP address
        ports: List of ports to scan (from masscan results)
        nmap_args: Nmap arguments from config (e.g., ["-sS", "-sV", "-sC", "-T2", "-Pn"])
        timeout: Max execution time in seconds

    Returns:
        (success: bool, raw_xml: str, error: Optional[str])
    """
    if not ports:
        return True, "", None  # No ports to scan = success

    # Create temp file for XML output
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        output_path = Path(f.name)

    try:
        # Build port list: "22,80,443,8080"
        port_string = ','.join(str(p) for p in sorted(set(ports)))

        # Filter nmap_args to remove any existing -p flags
        filtered_args = [arg for arg in nmap_args if not arg.startswith('-p')]

        # Check if -sS is present (requires sudo)
        needs_sudo = '-sS' in filtered_args

        # Build command
        cmd = []
        if needs_sudo:
            cmd.append('sudo')

        cmd.extend([
            settings.NMAP_PATH or 'nmap',
            *filtered_args,
            '-p', port_string,
            '-oX', str(output_path),
            ip
        ])

        # Execute
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Check if output file exists
        if not output_path.exists():
            return False, "", f"Nmap did not create output file. stderr: {result.stderr}"

        # Read raw XML output
        raw_xml = output_path.read_text()

        if not raw_xml.strip():
            return False, "", "Nmap produced empty output"

        # Nmap returns non-zero on some errors but zero on success
        if result.returncode != 0 and "error" in result.stderr.lower():
            return False, raw_xml, f"Nmap error: {result.stderr}"

        return True, raw_xml, None

    except subprocess.TimeoutExpired:
        return False, "", f"Nmap timed out after {timeout} seconds"
    except Exception as e:
        return False, "", f"Nmap execution failed: {str(e)}"
    finally:
        # Cleanup temp file
        if output_path.exists():
            output_path.unlink()

def run_nmap_discovery(
    ip: str,
    timing_template: str = "T4",
    timeout: int = 900
) -> Tuple[bool, str, Optional[str]]:
    """
    Execute nmap for port discovery scanning ALL 65,535 ports.

    This ensures no services are missed, regardless of what port they run on.
    Full port scans take longer but provide complete coverage.

    Args:
        ip: Target IP address
        timing_template: Nmap timing (T1-T5, default T4 for fast)
        timeout: Max execution time in seconds (default 900 = 15 minutes)

    Returns:
        (success: bool, raw_xml: str, error: Optional[str])
    """
    # Create temp file for XML output
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        output_path = Path(f.name)

    try:
        # Build command for full port discovery
        # -Pn: Skip host discovery (assume host is up)
        # -sT: TCP connect scan (works in Docker containers without raw sockets)
        # -p-: Scan ALL 65,535 ports
        # --open: Only show open ports (reduces output noise)
        cmd = [
            'sudo',
            settings.NMAP_PATH or 'nmap',
            '-Pn',
            '-sT',
            f'-{timing_template}',
            '--open',
            '-p-',  # ALL 65,535 ports
            '-oX', str(output_path),
            ip
        ]

        # Execute
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Check if output file exists
        if not output_path.exists():
            return False, "", f"Nmap did not create output file. stderr: {result.stderr}"

        # Read raw XML output
        raw_xml = output_path.read_text()

        if not raw_xml.strip():
            return False, "", "Nmap produced empty output"

        return True, raw_xml, None

    except subprocess.TimeoutExpired:
        return False, "", f"Nmap discovery timed out after {timeout} seconds"
    except Exception as e:
        return False, "", f"Nmap discovery failed: {str(e)}"
    finally:
        # Cleanup temp file
        if output_path.exists():
            output_path.unlink()


def parse_nmap_discovery(raw_xml: str) -> List[Dict]:
    """
    Parse nmap discovery XML output into a simple port list.

    Returns list of port dicts similar to masscan format:
    [
        {"port": 22, "protocol": "tcp", "state": "open"},
        {"port": 80, "protocol": "tcp", "state": "open"}
    ]
    """
    try:
        root = ET.fromstring(raw_xml)
        ports = []

        for host in root.findall('host'):
            ports_section = host.find('ports')
            if not ports_section:
                continue

            for port_elem in ports_section.findall('port'):
                port_id = port_elem.get('portid')
                protocol = port_elem.get('protocol', 'tcp')

                state_elem = port_elem.find('state')
                state = state_elem.get('state') if state_elem is not None else 'unknown'

                if state == 'open':
                    ports.append({
                        'port': int(port_id),
                        'protocol': protocol,
                        'state': 'open'
                    })

        return ports

    except ET.ParseError as e:
        raise ValueError(f"Invalid XML from nmap: {str(e)}")


def parse_nmap_xml(raw_xml: str) -> List[Dict]:
    """
    Parse nmap XML output into port details.

    Returns list of port dicts with service info:
    [
        {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service_name": "ssh",
            "product": "OpenSSH",
            "version": "8.2p1 Ubuntu 4ubuntu0.5",
            "extra_info": {...}  # NSE scripts, OS detection, etc.
        }
    ]
    """
    try:
        root = ET.fromstring(raw_xml)
        ports = []

        # Find all <host> elements
        for host in root.findall('host'):
            # Find <ports> section
            ports_section = host.find('ports')
            if not ports_section:
                continue

            # Find all <port> elements
            for port_elem in ports_section.findall('port'):
                port_id = port_elem.get('portid')
                protocol = port_elem.get('protocol', 'tcp')

                # Get state
                state_elem = port_elem.find('state')
                state = state_elem.get('state') if state_elem is not None else 'unknown'

                # Get service info
                service_elem = port_elem.find('service')
                service_name = None
                product = None
                version = None

                if service_elem is not None:
                    service_name = service_elem.get('name')
                    tunnel = service_elem.get('tunnel')  # Check for SSL/TLS tunnel

                    # Prepend tunnel to service name (e.g., "ssl/http")
                    # This matches nmap's display format and nuclei profile keys
                    if tunnel and service_name:
                        service_name = f"{tunnel}/{service_name}"

                    product = service_elem.get('product')
                    version_str = service_elem.get('version')

                    # Combine product + version
                    if product and version_str:
                        version = f"{product} {version_str}"
                    elif product:
                        version = product
                    elif version_str:
                        version = version_str

                # Get NSE script output (truncate to avoid bloat)
                extra_info = {}
                scripts = port_elem.findall('script')
                if scripts:
                    script_output = {}
                    for script in scripts[:5]:  # Limit to first 5 scripts
                        script_id = script.get('id')
                        script_out = script.get('output', '')
                        # Truncate long output
                        if len(script_out) > 200:
                            script_out = script_out[:200] + '...'
                        script_output[script_id] = script_out
                    extra_info['scripts'] = script_output

                ports.append({
                    'port': int(port_id),
                    'protocol': protocol,
                    'state': state,
                    'service_name': service_name,
                    'product': product,
                    'version': version,
                    'extra_info': extra_info if extra_info else None
                })

        return ports

    except ET.ParseError as e:
        raise ValueError(f"Invalid XML from nmap: {str(e)}")
