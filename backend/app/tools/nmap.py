import logging
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional, Dict
from ..core.config import settings
from ..core.validators import validate_target, validate_port_list, validate_nmap_args, ValidationError
from .base import ToolResult, failure_reason, read_output, run_command, temp_workdir

logger = logging.getLogger(__name__)

# Nmap's top 100 TCP ports (from nmap-services)
# These are the most commonly open ports across the internet
# Used for fast scans instead of --top-ports (which conflicts with -p flag)
NMAP_TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
    5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
    5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156
]

# Scan types that need raw sockets
_RAW_SOCKET_FLAGS = ('-sS', '-sU', '-sA', '-sW', '-sM', '-sN', '-sF', '-sX', '-sO', '-O', '-A')


def _privilege_args(nmap_args: List[str]) -> List[str]:
    """Extra args so raw-socket scans work for the non-root worker user.

    The worker image grants nmap ``cap_net_raw`` through file capabilities
    instead of running it as root via sudo. nmap only uses those capabilities
    when told it is privileged, hence ``--privileged``. If the capability is
    missing nmap exits non-zero and the run is recorded as failed.
    """
    if os.geteuid() == 0:
        return []
    if any(arg in _RAW_SOCKET_FLAGS for arg in nmap_args):
        return ['--privileged']
    return []


_SERVICE_DETECTION_FLAGS = ('-sV', '-sC', '-A')


def _connect_scan_for_service_detection(nmap_args: List[str]) -> List[str]:
    """Swap ``-sS`` for ``-sT`` when the run also does version/script detection.

    nmap 7.991 (the pinned build) binds every service-probe connection of a SYN
    scan to the same local address *and port*. The first probe connects; the
    next one to the same service fails with "Cannot assign requested address"
    and nmap gives up on that service, so anything that does not announce
    itself on connect (Tomcat, Elasticsearch, TLS-wrapped IMAP/POP3, ...) is
    left as "unknown" or a port-table guess. nmap 7.95 did not do this.

    This phase only looks at ports the discovery scan already found open, so a
    connect scan loses nothing. ``-sS`` on its own, UDP (``-sU``) and OS
    detection (``-O``) are left alone.
    """
    if '-sS' not in nmap_args or not any(arg in _SERVICE_DETECTION_FLAGS for arg in nmap_args):
        return nmap_args
    swapped: List[str] = []
    for arg in nmap_args:
        if arg == '-sS':
            arg = '-sT'
        if arg == '-sT' and '-sT' in swapped:
            continue
        swapped.append(arg)
    return swapped


def _execute_nmap(cmd: List[str], output_path: Path, timeout: int, label: str) -> ToolResult:
    """Run nmap writing XML to ``output_path`` and classify the outcome."""
    run = run_command(cmd, timeout=timeout)
    raw_xml = read_output(output_path)

    error = failure_reason(label, run, timeout)
    if error:
        # Keep whatever XML was written for debugging, but never report success
        return ToolResult.from_command(False, raw_xml if raw_xml.strip() else "", error, run)

    if not raw_xml.strip():
        return ToolResult.from_command(
            False, "", f"{label} produced empty output: {run.diagnostics()}", run)

    return ToolResult.from_command(True, raw_xml, None, run)


def run_nmap(
    ip: str,
    ports: List[int],
    nmap_args: List[str],
    timeout: int = 600
) -> ToolResult:
    """
    Execute nmap for service detection on specific ports.

    Args:
        ip: Target IP address
        ports: List of ports to scan (from masscan results)
        nmap_args: Nmap arguments from config (e.g., ["-sS", "-sV", "-sC", "-T2", "-Pn"])
        timeout: Max execution time in seconds

    Returns:
        ToolResult, unpackable as (success: bool, raw_xml: str, error: Optional[str])
    """
    if not ports:
        return ToolResult(True, "", None)  # No ports to scan = success

    # Validate inputs to prevent command injection
    try:
        ip = validate_target(ip)
        ports = validate_port_list(ports)
        # PEEK sets the port list itself: drop "-p..." (and a detached value)
        # before checking the rest against the allow-list. nmap_args comes from
        # a user-editable config, so this is enforced here as well as in the
        # API schema (configs stored before the schema check existed).
        without_ports = []
        skip_next = False
        for arg in nmap_args or []:
            if skip_next:
                skip_next = False
                continue
            if isinstance(arg, str) and arg.strip() == '-p':
                skip_next = True
                continue
            if isinstance(arg, str) and re.fullmatch(r'-p[0-9TUS:,\-]*', arg.strip()):
                continue
            without_ports.append(arg)
        filtered_args = validate_nmap_args(without_ports) if without_ports else []
        filtered_args = _connect_scan_for_service_detection(filtered_args)
    except ValidationError as e:
        return ToolResult(False, "", f"Input validation failed: {e}")

    with temp_workdir('nmap_') as workdir:
        output_path = workdir / 'scan.xml'

        # Build port list: "22,80,443,8080"
        port_string = ','.join(str(p) for p in sorted(set(ports)))

        cmd = [
            settings.NMAP_PATH or 'nmap',
            *_privilege_args(filtered_args),
            *filtered_args,
            '-p', port_string,
            '-oX', str(output_path),
            ip
        ]

        return _execute_nmap(cmd, output_path, timeout, "Nmap")


def run_nmap_discovery(
    ip: str,
    timing_template: str = "T4",
    timeout: int = 600,
    top_ports: Optional[int] = None,
    additional_ports: Optional[str] = None,
    full_scan: bool = False
) -> ToolResult:
    """
    Execute nmap for port discovery.

    By default scans top 100 ports (from NMAP_TOP_100_PORTS) plus any additional
    ports specified. Can optionally do full port scan of all 65,535 ports.

    Args:
        ip: Target IP address
        timing_template: Nmap timing (T1-T5, default T4 for fast)
        timeout: Max execution time in seconds (default 600 = 10 minutes)
        top_ports: DEPRECATED - no longer used (kept for backward compatibility)
        additional_ports: Comma-separated list of extra ports to always scan
        full_scan: If True, scan all 65,535 ports (slow, needs longer timeout)

    Returns:
        ToolResult, unpackable as (success: bool, raw_xml: str, error: Optional[str])
    """
    # Validate inputs to prevent command injection
    try:
        ip = validate_target(ip)
        if not re.fullmatch(r'T[0-5]', timing_template or ''):
            raise ValidationError(f"invalid timing template: {timing_template!r}")
    except ValidationError as e:
        return ToolResult(False, "", f"Input validation failed: {e}")

    with temp_workdir('nmap_') as workdir:
        output_path = workdir / 'discovery.xml'

        # Build command for port discovery
        # -Pn: Skip host discovery (assume host is up)
        # -sT: TCP connect scan (needs no raw sockets, so no sudo/capabilities)
        # --open: Only show open ports (reduces output noise)
        # --max-retries 2: Limit retries for filtered ports (default 10 is too slow)
        # --host-timeout: Cap total time per host to prevent filtered hosts from blocking
        cmd = [
            settings.NMAP_PATH or 'nmap',
            '-Pn',
            '-sT',
            f'-{timing_template}',
            '--open',
            '--max-retries', '2',
            '--host-timeout', f'{timeout}s',
        ]

        # Determine port specification
        if full_scan:
            # Full port scan - ALL 65,535 ports (slow!)
            cmd.append('-p-')
        else:
            # Fast port scan - combine top 100 ports + additional ports
            # NOTE: We use an explicit port list instead of --top-ports because
            # nmap ignores --top-ports when -p is also specified
            all_ports = set(NMAP_TOP_100_PORTS)

            # Add any additional ports from config
            if additional_ports:
                for p in additional_ports.split(','):
                    p = p.strip()
                    if p and p.isdigit():
                        port = int(p)
                        if 1 <= port <= 65535:
                            all_ports.add(port)
                        else:
                            logger.warning(f"Skipping out-of-range port in additional_ports: {port}")
                    elif p:  # Non-empty but not numeric
                        logger.warning(f"Skipping invalid port in additional_ports: '{p}'")

            # Build single -p argument with all ports
            port_string = ','.join(str(p) for p in sorted(all_ports))
            cmd.extend(['-p', port_string])

        cmd.extend(['-oX', str(output_path), ip])

        # The subprocess limit sits a little above --host-timeout so nmap can
        # give up on the host by itself and still write complete XML.
        return _execute_nmap(cmd, output_path, timeout + 30, "Nmap discovery")


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
            if ports_section is None:
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
            if ports_section is None:
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
