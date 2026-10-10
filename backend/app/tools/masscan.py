import json
import re
from typing import List, Optional
from ..core.config import settings
from ..core.validators import validate_target, ValidationError
from .base import ToolResult, failure_reason, read_output, run_command, temp_workdir

_INTERFACE_RE = re.compile(r'^[A-Za-z0-9_.:-]{1,32}$')

def run_masscan(
    ip: str,
    rate: int = 1000,
    interface: Optional[str] = None,
    timeout: int = 240
) -> ToolResult:
    """
    Execute masscan for port discovery.

    Args:
        ip: Target IP address
        rate: Packets per second (PPS)
        interface: Network interface (e.g., 'en0', 'eth0')
        timeout: Max execution time in seconds

    Returns:
        ToolResult, unpackable as (success: bool, raw_json: str, error: Optional[str]).
        Only a clean exit with an empty report means "no open ports"; a
        non-zero exit (e.g. missing raw-socket capability) is a failure.
    """
    # Validate inputs to prevent command/argument injection
    try:
        ip = validate_target(ip)
        rate = int(rate)
        if interface is not None and not _INTERFACE_RE.match(interface):
            raise ValidationError(f"invalid interface name: {interface!r}")
    except (ValidationError, TypeError, ValueError) as e:
        return ToolResult(False, "", f"Input validation failed: {e}")

    with temp_workdir('masscan_') as workdir:
        output_path = workdir / 'masscan.json'

        # No sudo: the worker runs as a non-root user and the image grants
        # masscan cap_net_raw/cap_net_admin via file capabilities.
        cmd = [
            settings.MASSCAN_PATH or 'masscan',
            ip,
            '-p0-65535',  # Scan all ports
            f'--rate={rate}',
            '--output-format', 'json',
            '--output-filename', str(output_path)
        ]

        if interface:
            cmd.extend(['--interface', interface])

        run = run_command(cmd, timeout=timeout)
        raw_json = read_output(output_path)

        error = failure_reason("Masscan", run, timeout)
        if error:
            return ToolResult.from_command(False, raw_json if raw_json.strip() else "", error, run)

        if not raw_json.strip():
            # Clean exit and empty report = no open ports
            raw_json = "[]"

        return ToolResult.from_command(True, raw_json, None, run)


def parse_masscan_output(raw_json: str) -> List[dict]:
    """
    Parse masscan JSON output into port list.

    Input format:
    [
        {
            "ip": "192.168.1.1",
            "timestamp": "1234567890",
            "ports": [
                {"port": 22, "proto": "tcp", "status": "open"},
                {"port": 80, "proto": "tcp", "status": "open"}
            ]
        }
    ]

    Returns:
        [
            {"port": 22, "protocol": "tcp", "state": "open"},
            {"port": 80, "protocol": "tcp", "state": "open"}
        ]
    """
    try:
        data = json.loads(raw_json)

        if not data:
            return []

        ports = []
        for entry in data:
            for port_info in entry.get("ports", []):
                ports.append({
                    "port": port_info["port"],
                    "protocol": port_info.get("proto", "tcp"),
                    "state": port_info.get("status", "open")
                })

        return ports

    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON from masscan: {str(e)}")
