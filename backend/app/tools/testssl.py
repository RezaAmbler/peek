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
import json
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any

from ..core.config import settings
from ..core.validators import validate_target, validate_port, ValidationError
from .base import EXIT_NOT_RUN, failure_reason, read_output, run_command, temp_workdir

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
    command_line: Optional[str] = None  # Exact command that ran
    exit_code: Optional[int] = None  # Real exit code (124 = timeout, 127 = not installed)
    timed_out: bool = False


# testssl.sh reserves exit codes >= 242 for fatal errors (ERR_CHILD=242 ...
# ERR_BASH=255). Lower non-zero codes count "ambiguous" findings of a scan that ran.
TESTSSL_FATAL_EXIT_MIN = 242


def _fatal_finding(parsed_data) -> Optional[str]:
    """Return testssl's FATAL message, for both the flat and the pretty JSON layout."""
    if not isinstance(parsed_data, list):
        return None
    for item in parsed_data:
        if not isinstance(item, dict):
            continue
        if item.get('severity') == 'FATAL':
            return item.get('finding') or 'Fatal error'
        for nested in item.get('scanResult') or []:
            if isinstance(nested, dict) and nested.get('severity') == 'FATAL':
                return nested.get('finding') or 'Fatal error'
    return None


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
    # Validate inputs to prevent command/argument injection
    try:
        host = validate_target(host)
        port = validate_port(port)
    except ValidationError as e:
        return TestsslOutput(
            success=False,
            error=f"Input validation failed: {e}",
            host=host,
            port=port,
            exit_code=EXIT_NOT_RUN,
        )

    with temp_workdir('testssl_') as workdir:
        output_path = workdir / 'output.json'

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
            '--connect-timeout=10',
            '--openssl-timeout=10',
        ]

        if fast_mode:
            cmd.append('--fast')

        # Add target (host:port)
        cmd.append(f'{host}:{port}')

        logger.info(f"Running testssl: {' '.join(cmd)}")

        run = run_command(cmd, timeout=timeout)
        meta = dict(host=host, port=port, command_line=run.command_line,
                    exit_code=run.exit_code, timed_out=run.timed_out)

        # Read whatever was written (partial output on timeout is kept for debugging)
        raw_json = read_output(output_path)

        if not run.ran:
            error = failure_reason("testssl.sh", run, timeout)
            logger.warning(f"testssl.sh failed for {host}:{port}: {error}")
            return TestsslOutput(success=False, raw_json=raw_json or None, error=error, **meta)

        if not raw_json.strip():
            return TestsslOutput(
                success=False,
                error=(f"testssl.sh produced no output (exit code {run.returncode}): "
                       f"{run.diagnostics()}"),
                **meta
            )

        # Parse JSON
        try:
            parsed_data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            return TestsslOutput(
                success=False,
                raw_json=raw_json,
                error=f"Invalid JSON output (exit code {run.returncode}): {e}",
                **meta
            )

        # Check for scan errors in output
        fatal = _fatal_finding(parsed_data)
        if fatal:
            return TestsslOutput(
                success=False,
                raw_json=raw_json,
                parsed_data=parsed_data,
                error=fatal,
                **meta
            )

        if run.returncode >= TESTSSL_FATAL_EXIT_MIN:
            return TestsslOutput(
                success=False,
                raw_json=raw_json,
                parsed_data=parsed_data,
                error=f"testssl.sh exited with fatal code {run.returncode}: {run.diagnostics()}",
                **meta
            )

        logger.info(f"testssl.sh completed for {host}:{port}")

        return TestsslOutput(
            success=True,
            raw_json=raw_json,
            parsed_data=parsed_data,
            **meta
        )


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
