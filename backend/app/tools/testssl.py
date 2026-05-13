"""
testssl.sh tool wrapper for deep TLS/SSL security analysis.

testssl.sh provides comprehensive TLS posture analysis including:
- Protocol versions (SSLv2/3, TLSv1.0-1.3)
- Cipher suites with security ratings
- Certificate chain validation
- Known vulnerabilities (Heartbleed, POODLE, BEAST, DROWN, ROBOT, etc.)
- Forward secrecy evaluation
- HSTS, HPKP, certificate transparency
"""

import subprocess
import tempfile
import json
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

from ..core.config import settings
from ..core.validators import SHELL_METACHARACTERS

logger = logging.getLogger(__name__)

# Default testssl.sh path
TESTSSL_PATH = getattr(settings, 'TESTSSL_PATH', 'testssl')


@dataclass
class TestsslOutput:
    """Structured output from testssl.sh execution."""
    success: bool
    raw_json: Optional[str] = None
    parsed_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None


def run_testssl(
    host: str,
    port: int,
    timeout: int = 300,
    fast_mode: bool = True,
) -> TestsslOutput:
    """
    Execute testssl.sh against a host:port.

    Args:
        host: Target IP address or hostname
        port: Port number
        timeout: Max execution time in seconds (default 300)
        fast_mode: Use --fast flag for quicker scans (default True)

    Returns:
        TestsslOutput with parsed results and raw JSON
    """
    # Validate host to prevent command injection
    dangerous_chars = SHELL_METACHARACTERS.intersection(host)
    if dangerous_chars:
        return TestsslOutput(
            success=False,
            error=f"Invalid host: contains shell metacharacters {dangerous_chars}",
            host=host,
            port=port
        )

    # Create temp file for JSON output
    temp_dir = tempfile.mkdtemp(prefix='testssl_')
    output_path = Path(temp_dir) / 'output.json'

    try:
        # Build command
        # testssl.sh options:
        # --jsonfile: JSON output file
        # --fast: Don't check for all ciphers, just common ones
        # --warnings batch: Don't pause for warnings
        # --quiet: Less console output
        # --sneaky: Use common browser User-Agent
        # --connect-timeout: Connection timeout
        # --openssl-timeout: Timeout for openssl operations
        cmd = [
            TESTSSL_PATH,
            f'--jsonfile={output_path}',
            '--warnings', 'batch',
            '--quiet',
            '--sneaky',
            f'--connect-timeout=10',
            f'--openssl-timeout=10',
        ]

        if fast_mode:
            cmd.append('--fast')

        # Add target (host:port)
        cmd.append(f'{host}:{port}')

        cmd_str = ' '.join(cmd)
        logger.info(f"Running testssl: {cmd_str}")

        # Execute
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Check if output file exists
        if not output_path.exists():
            return TestsslOutput(
                success=False,
                error=f"testssl.sh did not create output file. stderr: {result.stderr[:500] if result.stderr else 'none'}",
                host=host,
                port=port
            )

        # Read raw JSON output
        raw_json = output_path.read_text()

        if not raw_json.strip():
            return TestsslOutput(
                success=False,
                error="testssl.sh produced empty output",
                host=host,
                port=port
            )

        # Parse JSON
        try:
            parsed_data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            return TestsslOutput(
                success=False,
                raw_json=raw_json,
                error=f"Invalid JSON output: {e}",
                host=host,
                port=port
            )

        # Check for scan errors in output
        if isinstance(parsed_data, list) and len(parsed_data) > 0:
            # testssl.sh outputs an array of scan results
            scan_result = parsed_data[0] if isinstance(parsed_data[0], dict) else {}
            if scan_result.get('scanResult', [{}])[0].get('severity') == 'FATAL':
                return TestsslOutput(
                    success=False,
                    raw_json=raw_json,
                    parsed_data=parsed_data,
                    error=scan_result.get('scanResult', [{}])[0].get('finding', 'Fatal error'),
                    host=host,
                    port=port
                )

        logger.info(f"testssl.sh completed for {host}:{port}")

        return TestsslOutput(
            success=True,
            raw_json=raw_json,
            parsed_data=parsed_data,
            host=host,
            port=port
        )

    except subprocess.TimeoutExpired:
        logger.warning(f"testssl.sh timed out after {timeout}s for {host}:{port}")
        # Try to read partial output
        partial_json = None
        if output_path.exists():
            try:
                partial_json = output_path.read_text()
            except Exception:
                pass

        return TestsslOutput(
            success=False,
            raw_json=partial_json,
            error=f"Timeout after {timeout}s",
            host=host,
            port=port
        )

    except FileNotFoundError:
        logger.error("testssl.sh not found. Install from: https://github.com/drwetter/testssl.sh")
        return TestsslOutput(
            success=False,
            error="testssl.sh not found",
            host=host,
            port=port
        )

    except Exception as e:
        logger.error(f"testssl.sh error for {host}:{port}: {e}")
        return TestsslOutput(
            success=False,
            error=str(e),
            host=host,
            port=port
        )

    finally:
        # Cleanup temp files
        try:
            if output_path.exists():
                output_path.unlink()
            Path(temp_dir).rmdir()
        except Exception:
            pass


def check_testssl_available() -> bool:
    """Check if testssl.sh is available on the system."""
    try:
        result = subprocess.run(
            [TESTSSL_PATH, '--version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        # testssl.sh returns version info on stdout or stderr
        return 'testssl' in (result.stdout + result.stderr).lower()
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return False
