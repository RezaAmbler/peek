import subprocess
import json
import tempfile
from pathlib import Path
from typing import Tuple, List, Optional
from ..core.config import settings

def run_masscan(
    ip: str,
    rate: int = 1000,
    interface: Optional[str] = None,
    timeout: int = 240
) -> Tuple[bool, str, Optional[str]]:
    """
    Execute masscan for port discovery.

    Args:
        ip: Target IP address
        rate: Packets per second (PPS)
        interface: Network interface (e.g., 'en0', 'eth0')
        timeout: Max execution time in seconds

    Returns:
        (success: bool, raw_json: str, error: Optional[str])
    """
    # Create temp file for output
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        output_path = Path(f.name)

    try:
        # Build command
        cmd = [
            'sudo',
            settings.MASSCAN_PATH or 'masscan',
            ip,
            '-p0-65535',  # Scan all ports
            f'--rate={rate}',
            '--output-format', 'json',
            '--output-filename', str(output_path)
        ]

        if interface:
            cmd.extend(['--interface', interface])

        # Execute
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Masscan sometimes returns non-zero even on success
        # Check if output file exists and has content
        if not output_path.exists():
            return False, "", f"Masscan did not create output file. stderr: {result.stderr}"

        # Read raw JSON output
        raw_json = output_path.read_text()

        if not raw_json.strip():
            # Empty output = no open ports (this is success)
            raw_json = "[]"

        return True, raw_json, None

    except subprocess.TimeoutExpired:
        return False, "", f"Masscan timed out after {timeout} seconds"
    except Exception as e:
        return False, "", f"Masscan execution failed: {str(e)}"
    finally:
        # Cleanup temp file
        if output_path.exists():
            output_path.unlink()

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
