"""httpx HTTP prober integration with screenshot and vhost discovery support."""
import subprocess
import json
import logging
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Any

from ..core.config import settings
from ..core.validators import SHELL_METACHARACTERS
from .base import EXIT_NOT_RUN, failure_reason, read_output, run_command

logger = logging.getLogger(__name__)


@dataclass
class HttpxOutput:
    """Structured output from httpx execution."""
    success: bool
    raw_json: Optional[str] = None
    error: Optional[str] = None
    screenshot_path: Optional[Path] = None  # Temporary path to screenshot file
    command_line: Optional[str] = None  # Exact command that ran
    exit_code: Optional[int] = None  # Real exit code (124 = timeout, 127 = not installed)
    timed_out: bool = False
    temp_dir: Optional[Path] = None  # Only set while a screenshot is waiting to be collected

    def cleanup(self) -> None:
        """Remove the temp directory holding the screenshot (safe to call twice)."""
        if self.temp_dir is not None:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = None
            self.screenshot_path = None


def run_httpx(
    target: str,
    timeout: int = 30,
    follow_redirects: bool = True,
    tech_detect: bool = True,
    tls_probe: bool = True,
    jarm: bool = True,
    screenshots: bool = False,
    screenshot_timeout: int = 10,
    vhost_discovery: bool = False,
    retries: int = 2,
) -> HttpxOutput:
    """
    Execute httpx HTTP prober.

    Flags and JSON fields are verified against httpx v1.12.0 (see docs/tools/httpx.md).

    Args:
        target: URL or host:port to probe (e.g., "http://192.168.1.1:8080")
        timeout: HTTP request timeout in seconds
        follow_redirects: Follow HTTP redirects
        tech_detect: Enable technology detection
        tls_probe: Grab TLS data (version, cipher) from the probed endpoint
        jarm: Enable JARM fingerprinting
        screenshots: Enable webpage screenshot capture (needs Chromium in the image)
        screenshot_timeout: Max time for the headless screenshot (seconds)
        vhost_discovery: Enable virtual host discovery
        retries: Number of retries for failed connections (default 2)

    Returns:
        HttpxOutput. If a screenshot was captured the caller must call
        ``output.cleanup()`` once it has copied the file; otherwise nothing is
        left on disk.
    """
    # Validate target to prevent command injection
    # httpx targets can be URLs (http://...) so we just check for shell metacharacters
    dangerous_chars = SHELL_METACHARACTERS.intersection(target)
    if dangerous_chars or target.startswith('-'):
        return HttpxOutput(
            success=False,
            error=f"Invalid target: contains shell metacharacters {dangerous_chars or '-'}",
            exit_code=EXIT_NOT_RUN,
        )

    # Create temp directory for output files (path inside does not exist yet)
    temp_dir = Path(tempfile.mkdtemp(prefix='httpx_'))
    output_path = temp_dir / 'output.json'
    screenshot_dir = temp_dir / 'screenshots'
    keep_temp_dir = False

    try:
        # Build command
        cmd = [
            settings.HTTPX_PATH or 'httpx',
            '-u', target,
            '-json',
            '-silent',
            '-nc',  # No color
            '-duc',  # No update check: the binary is pinned by the image
            '-timeout', str(timeout),
            '-retries', str(retries),  # Retry failed connections
            '-sc',   # Status code
            '-cl',   # Content length
            '-ct',   # Content type
            '-title',
            '-server',
            '-hash', 'md5',
            '-o', str(output_path),
        ]

        if follow_redirects:
            # -include-chain is what puts the redirect chain in the JSON
            cmd.extend(['-fr', '-maxr', '10', '-include-chain'])

        if tech_detect:
            cmd.append('-td')

        if tls_probe:
            # -tls-grab fills the "tls" JSON object. (-tls-probe would also send
            # probes to every hostname found in the certificate, i.e. hosts
            # outside the scan target, so it is deliberately not used.)
            cmd.append('-tls-grab')

        if jarm:
            cmd.append('-jarm')

        # CDN detection
        cmd.append('-cdn')

        # Screenshot capture (opt-in)
        if screenshots:
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            cmd.extend([
                '-ss',
                '-system-chrome',  # Use the image's Chromium, never download one at scan time
                '-ho=--no-sandbox',  # Chromium's sandbox cannot start inside the container
                '-esb', '-ehb',  # Keep the PNG bytes / rendered DOM out of the JSON
                '-srd', str(screenshot_dir),
            ])
            if screenshot_timeout > 0:
                cmd.extend(['-st', f'{int(screenshot_timeout)}s'])

        # Virtual host discovery
        if vhost_discovery:
            cmd.append('-vhost')

        logger.info(f"Running httpx: {' '.join(cmd)}")

        # Calculate total timeout (account for retries and add buffer)
        # Each retry can take up to 'timeout' seconds
        total_timeout = (timeout * (retries + 1)) + 30
        if screenshots:
            total_timeout += screenshot_timeout + 10

        run = run_command(cmd, timeout=total_timeout)
        meta = dict(command_line=run.command_line, exit_code=run.exit_code, timed_out=run.timed_out)
        raw_json = read_output(output_path)

        error = failure_reason("httpx", run, total_timeout)
        if error:
            logger.warning(f"httpx failed for {target}: {error}")
            return HttpxOutput(success=False, raw_json=raw_json or None, error=error, **meta)

        if not raw_json.strip():
            # Clean exit, nothing written: the port did not answer HTTP
            logger.warning(f"httpx produced empty output for {target}")
            return HttpxOutput(success=False, error="No HTTP response", **meta)

        logger.info(f"httpx completed for {target}")

        # Find screenshot file if enabled.
        # httpx writes it to <srd>/screenshot/<host>/<hash>.png
        screenshot_file = None
        if screenshots and screenshot_dir.exists():
            png_files = sorted(screenshot_dir.rglob('*.png'))
            if png_files:
                screenshot_file = png_files[0]
                keep_temp_dir = True
                logger.info(f"Screenshot captured: {screenshot_file}")
            else:
                logger.warning(f"httpx screenshot requested but none captured for {target}: {run.diagnostics()}")

        return HttpxOutput(
            success=True,
            raw_json=raw_json,
            screenshot_path=screenshot_file,
            temp_dir=temp_dir if keep_temp_dir else None,
            **meta,
        )

    except Exception as e:
        logger.error(f"httpx error for {target}: {e}")
        return HttpxOutput(success=False, error=str(e), exit_code=EXIT_NOT_RUN)
    finally:
        # Everything is removed here unless a screenshot is waiting for the
        # caller, who then owns the directory via HttpxOutput.cleanup().
        if not keep_temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


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
        if not isinstance(data, dict):
            logger.warning("httpx JSON line is not an object")
            return None

        tls_data = data.get('tls') or data.get('tls-grab')
        cdn, waf = _extract_cdn_waf(data)

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
            'cdn': cdn,
            'waf': waf,
            'final_url': data.get('final_url') or data.get('final-url'),
            'redirect_chain': _extract_redirect_chain(data.get('chain')),
            'response_time_ms': _parse_response_time(data.get('time') or data.get('response_time')),
            'body_hash': _extract_hash(data.get('hash') or data.get('hashes')),
            'tls_version': _extract_tls_version(tls_data),
            'tls_cipher': _extract_tls_cipher(tls_data),
            # httpx >= 1.3 names the field "jarm_hash"; older builds used "jarm"
            'jarm_hash': data.get('jarm_hash') or data.get('jarm'),
            'virtual_hosts': _extract_virtual_hosts(data),
            'vhost_detected': data.get('vhost') is True,
            'failed': data.get('failed', False),
        }
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse httpx JSON: {e}")
        return None
    except Exception as e:
        logger.error(f"Error parsing httpx output: {e}")
        return None


def _extract_cdn_waf(data: Dict[str, Any]):
    """Map httpx's cdn/cdn_name/cdn_type fields to (cdn_name, waf_name).

    httpx reports ``cdn`` as a boolean plus ``cdn_name`` and ``cdn_type``
    ("cdn", "waf" or "cloud"); older builds put the name in ``cdn`` directly.
    """
    name = data.get('cdn_name')
    kind = (data.get('cdn_type') or '').lower()
    legacy = data.get('cdn')
    if not name and isinstance(legacy, str):
        name = legacy
    waf = data.get('waf') if isinstance(data.get('waf'), str) else None
    if name and kind == 'waf':
        return None, waf or name
    return name or None, waf


def _extract_redirect_chain(chain) -> List[str]:
    """Reduce httpx's chain items to the list of requested URLs."""
    urls: List[str] = []
    if not isinstance(chain, list):
        return urls
    for item in chain:
        if isinstance(item, str):
            urls.append(item)
        elif isinstance(item, dict):
            url = item.get('request-url') or item.get('request_url') or item.get('location')
            if url:
                urls.append(url)
    return urls


def _extract_virtual_hosts(data: Dict[str, Any]) -> List[str]:
    """Virtual host names, if the tool reported any.

    httpx's ``vhost`` field is a boolean ("this server routes by Host header"),
    not a list of names, so for httpx itself this is normally empty.
    """
    for key in ('virtual_hosts', 'vhost'):
        value = data.get(key)
        if isinstance(value, list):
            return [str(v) for v in value]
    return []


def _parse_response_time(time_str: Optional[str]) -> Optional[int]:
    """Parse response time (Go duration string such as "245.1ms" or "1.2s") to milliseconds."""
    if not time_str:
        return None
    try:
        if isinstance(time_str, (int, float)):
            return int(time_str)
        time_str = str(time_str).strip().lower()
        for suffix, factor in (('ms', 1), ('µs', 0.001), ('us', 0.001), ('ns', 0.000001), ('s', 1000)):
            if time_str.endswith(suffix):
                return int(float(time_str[:-len(suffix)]) * factor)
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
