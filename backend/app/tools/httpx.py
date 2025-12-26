"""httpx HTTP prober integration."""
import subprocess
import json
import logging
import tempfile
from pathlib import Path
from typing import Tuple, Optional, List, Dict, Any

from ..core.config import settings

logger = logging.getLogger(__name__)


def run_httpx(
    target: str,
    timeout: int = 30,
    follow_redirects: bool = True,
    tech_detect: bool = True,
    tls_probe: bool = True,
    jarm: bool = True
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Execute httpx HTTP prober.

    Args:
        target: URL or host:port to probe (e.g., "http://192.168.1.1:8080")
        timeout: HTTP request timeout in seconds
        follow_redirects: Follow HTTP redirects
        tech_detect: Enable technology detection
        tls_probe: Enable TLS probing
        jarm: Enable JARM fingerprinting

    Returns:
        Tuple of (success, json_output, error_message)
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        output_path = f.name

    try:
        # Build command
        cmd = [
            settings.HTTPX_PATH or 'httpx',
            '-u', target,
            '-json',
            '-silent',
            '-nc',  # No color
            '-timeout', str(timeout),
            '-sc',   # Status code
            '-cl',   # Content length
            '-ct',   # Content type
            '-title',
            '-server',
            '-hash', 'md5',
            '-o', output_path,
        ]

        if follow_redirects:
            cmd.extend(['-fr', '-maxr', '10'])

        if tech_detect:
            cmd.append('-td')

        if tls_probe:
            cmd.append('-tls-probe')

        if jarm:
            cmd.append('-jarm')

        # CDN detection
        cmd.append('-cdn')

        cmd_str = ' '.join(cmd)
        logger.info(f"Running httpx: {cmd_str}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 30  # Buffer beyond HTTP timeout
        )

        # Read output file
        output_file = Path(output_path)
        if output_file.exists():
            raw_json = output_file.read_text()
            if raw_json.strip():
                logger.info(f"httpx completed for {target}")
                return True, raw_json, None
            else:
                # Empty output = no HTTP response (connection failed)
                logger.warning(f"httpx produced empty output for {target}")
                return False, None, "No HTTP response"
        else:
            stderr_preview = result.stderr[:500] if result.stderr else "no stderr"
            logger.warning(f"httpx did not produce output for {target}: {stderr_preview}")
            return False, None, f"No output file. stderr: {stderr_preview}"

    except subprocess.TimeoutExpired:
        logger.warning(f"httpx timed out after {timeout}s for {target}")
        return False, None, f"Timeout after {timeout} seconds"
    except FileNotFoundError:
        logger.error("httpx not found. Install from: https://github.com/projectdiscovery/httpx")
        return False, None, "httpx not found"
    except Exception as e:
        logger.error(f"httpx error for {target}: {e}")
        return False, None, str(e)
    finally:
        # Cleanup
        Path(output_path).unlink(missing_ok=True)


def parse_httpx_output(raw_json: str) -> Optional[Dict[str, Any]]:
    """
    Parse httpx JSON output into structured data.

    Args:
        raw_json: Raw JSON string from httpx (one JSON object per line)

    Returns:
        Parsed dictionary or None if parsing fails

    Example input:
    {"url":"http://192.168.1.184:8888","status_code":200,"title":"Apache2 Ubuntu Default Page",
     "webserver":"Apache/2.4.41","tech":["Apache","Ubuntu"],"content_length":10918}
    """
    if not raw_json or not raw_json.strip():
        return None

    try:
        # httpx outputs one JSON object per line, take the first one
        first_line = raw_json.strip().split('\n')[0]
        data = json.loads(first_line)

        return {
            'url': data.get('url'),
            'input': data.get('input'),
            'status_code': data.get('status_code') or data.get('status-code'),
            'content_length': data.get('content_length') or data.get('content-length'),
            'content_type': data.get('content_type') or data.get('content-type'),
            'title': data.get('title'),
            'webserver': data.get('webserver'),
            'method': data.get('method', 'GET'),
            'technologies': data.get('tech') or data.get('technologies') or [],
            'cdn': data.get('cdn'),
            'waf': data.get('waf'),
            'final_url': data.get('final_url') or data.get('final-url'),
            'redirect_chain': data.get('chain') or [],
            'response_time_ms': _parse_response_time(data.get('time') or data.get('response_time')),
            'body_hash': _extract_hash(data.get('hash') or data.get('hashes')),
            'tls_version': _extract_tls_version(data.get('tls') or data.get('tls-grab')),
            'tls_cipher': _extract_tls_cipher(data.get('tls') or data.get('tls-grab')),
            'jarm_hash': data.get('jarm'),
            'failed': data.get('failed', False),
        }
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse httpx JSON: {e}")
        return None
    except Exception as e:
        logger.error(f"Error parsing httpx output: {e}")
        return None


def _parse_response_time(time_str: Optional[str]) -> Optional[int]:
    """Parse response time string to milliseconds."""
    if not time_str:
        return None
    try:
        if isinstance(time_str, (int, float)):
            return int(time_str)
        # Handle formats like "245ms", "1.2s"
        time_str = str(time_str).lower()
        if 'ms' in time_str:
            return int(float(time_str.replace('ms', '')))
        elif 's' in time_str:
            return int(float(time_str.replace('s', '')) * 1000)
        return int(float(time_str))
    except (ValueError, TypeError):
        return None


def _extract_hash(hash_data) -> Optional[str]:
    """Extract MD5 hash from hash data."""
    if not hash_data:
        return None
    if isinstance(hash_data, str):
        return hash_data
    if isinstance(hash_data, dict):
        return hash_data.get('body_md5') or hash_data.get('body-md5') or hash_data.get('md5')
    return None


def _extract_tls_version(tls_data) -> Optional[str]:
    """Extract TLS version from TLS data."""
    if not tls_data:
        return None
    if isinstance(tls_data, str):
        return tls_data
    if isinstance(tls_data, dict):
        return tls_data.get('version') or tls_data.get('tls_version')
    return None


def _extract_tls_cipher(tls_data) -> Optional[str]:
    """Extract TLS cipher from TLS data."""
    if not tls_data:
        return None
    if isinstance(tls_data, dict):
        return tls_data.get('cipher')
    return None


def check_httpx_available() -> bool:
    """Check if httpx is available on the system."""
    try:
        result = subprocess.run(
            [settings.HTTPX_PATH or 'httpx', '-version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return False
