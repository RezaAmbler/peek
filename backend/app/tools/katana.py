"""Katana web crawler integration for endpoint discovery."""
import subprocess
import json
import logging
from dataclasses import dataclass, field
from typing import List, Optional

from ..core.config import settings
from ..core.validators import SHELL_METACHARACTERS
from .base import EXIT_NOT_RUN, failure_reason, read_output, run_command, temp_workdir

logger = logging.getLogger(__name__)


@dataclass
class KatanaEndpoint:
    """Single discovered endpoint from Katana."""
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    depth: int = 0
    source: str = "crawl"  # crawl, form, js, etc.


@dataclass
class KatanaOutput:
    """Structured output from Katana execution."""
    success: bool
    endpoints: List[KatanaEndpoint] = field(default_factory=list)
    raw_output: Optional[str] = None
    error: Optional[str] = None
    target_url: Optional[str] = None
    command_line: Optional[str] = None  # Exact command that ran
    exit_code: Optional[int] = None  # Real exit code (124 = timeout, 127 = not installed)
    timed_out: bool = False


# Per-request timeout handed to katana's -timeout (seconds)
REQUEST_TIMEOUT_SECONDS = 10


def run_katana(
    target_url: str,
    depth: int = 2,
    timeout: int = 120,
    concurrency: int = 10,
    rate_limit: int = 150,
    max_endpoints: int = 500,
    headless: bool = False,
    request_timeout: int = REQUEST_TIMEOUT_SECONDS,
) -> KatanaOutput:
    """
    Execute Katana web crawler for endpoint discovery.

    Flags and JSON fields are verified against katana v1.8.0 (see docs/tools/katana.md).

    Args:
        target_url: Base URL to crawl (e.g., "https://example.com")
        depth: Maximum crawl depth (default 2)
        timeout: Overall crawl budget in seconds (default 120), passed as -crawl-duration
        concurrency: Number of concurrent requests (default 10)
        rate_limit: Max requests per second (default 150)
        max_endpoints: Maximum endpoints to discover (default 500)
        headless: Use headless browser for JS rendering (needs Chromium in the image)
        request_timeout: Per-request timeout in seconds, passed as -timeout

    Returns:
        KatanaOutput with discovered endpoints, raw output, and any errors
    """
    # Validate target to prevent command injection
    dangerous_chars = SHELL_METACHARACTERS.intersection(target_url)
    if dangerous_chars or target_url.startswith('-'):
        return KatanaOutput(
            success=False,
            error=f"Invalid target: contains shell metacharacters {dangerous_chars or '-'}",
            target_url=target_url,
            exit_code=EXIT_NOT_RUN,
        )

    with temp_workdir('katana_') as workdir:
        output_path = workdir / 'output.jsonl'

        # Build command
        cmd = [
            settings.KATANA_PATH or 'katana',
            '-u', target_url,
            '-jsonl',  # JSON Lines output
            '-silent',
            '-nc',  # No color
            '-duc',  # No update check: the binary is pinned by the image
            '-d', str(depth),  # Max depth
            '-c', str(concurrency),  # Concurrency
            '-rate-limit', str(rate_limit),  # Requests per second
            # katana's -timeout is per request; the overall budget is -crawl-duration
            '-timeout', str(request_timeout),
            '-crawl-duration', f'{int(timeout)}s',
            '-field-scope', 'rdn',  # Stay on same root domain (prevent crawling off-target)
            '-omit-raw', '-omit-body',  # Keep raw requests/responses and bodies out of the JSONL
            '-o', str(output_path),
        ]

        # Headless mode for JavaScript rendering
        if headless:
            # Use the image's Chromium; its sandbox cannot start inside the container
            cmd.extend(['-headless', '-system-chrome', '-no-sandbox'])

        # Automatic form filling (passive, doesn't submit)
        cmd.append('-automatic-form-fill')

        logger.info(f"Running katana: {' '.join(cmd)}")

        # Buffer for startup/shutdown beyond the crawl budget
        total_timeout = timeout + 30
        run = run_command(cmd, timeout=total_timeout)
        meta = dict(command_line=run.command_line, exit_code=run.exit_code, timed_out=run.timed_out)

        raw_output = read_output(output_path)
        endpoints = _parse_katana_output(raw_output, max_endpoints)

        error = failure_reason("Katana", run, total_timeout)
        if error:
            if endpoints:
                # Keep what was crawled, but the run is recorded as failed/partial
                error = f"{error} (partial results: {len(endpoints)} endpoints)"
            logger.warning(f"Katana failed for {target_url}: {error}")
            return KatanaOutput(
                success=False,
                endpoints=endpoints,
                raw_output=raw_output,
                error=error,
                target_url=target_url,
                **meta,
            )

        if endpoints:
            logger.info(f"Katana discovered {len(endpoints)} endpoint(s) from {target_url}")
        elif run.stderr.strip():
            logger.warning(f"Katana no endpoints, stderr: {run.diagnostics()}")

        # Clean exit with no endpoints is not an error, just nothing to crawl
        return KatanaOutput(
            success=True,
            endpoints=endpoints,
            raw_output=raw_output,
            target_url=target_url,
            **meta,
        )


def _parse_katana_output(raw_output: str, max_endpoints: int) -> List[KatanaEndpoint]:
    """Parse Katana JSONL into endpoints, skipping malformed lines."""
    endpoints: List[KatanaEndpoint] = []
    for line in (raw_output or "").splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            logger.debug(f"Skipping non-JSON line: {line[:100]}")
            continue
        if not isinstance(data, dict):
            continue
        endpoint = _parse_katana_line(data)
        if endpoint:
            endpoints.append(endpoint)
            if len(endpoints) >= max_endpoints:
                logger.info(f"Reached max_endpoints limit ({max_endpoints})")
                break
    return endpoints


def _parse_katana_line(data: dict) -> Optional[KatanaEndpoint]:
    """Parse a single Katana JSONL line into KatanaEndpoint."""
    try:
        request = data.get('request') or {}
        response = data.get('response') or {}
        if not isinstance(request, dict):
            request = {}
        if not isinstance(response, dict):
            response = {}

        # Katana output format varies - handle both request wrapper and flat URL
        url = request.get('endpoint') or data.get('endpoint') or data.get('url')
        if not url:
            return None

        # Get method from request object or default to GET
        method = request.get('method') or data.get('method') or 'GET'

        # Get response details if available
        status_code = response.get('status_code') or data.get('status_code')
        content_length = response.get('content_length') or data.get('content_length')

        # katana has no content_type field: it is a response header. Header
        # names keep the server's spelling ("Content-Type" from katana 1.8.0
        # against hellbox), so the lookup must not depend on their case.
        headers = response.get('headers') or {}
        if not isinstance(headers, dict):
            headers = {}
        lowered = {str(name).lower().replace('_', '-'): value for name, value in headers.items()}
        content_type = (
            lowered.get('content-type')
            or response.get('content_type') or data.get('content_type')
        )

        # katana does not emit depth (json:"-"); request.source is the page
        # the link was found on, request.tag/attribute say how it was found
        depth = data.get('depth', 0)
        source = request.get('tag') or data.get('source') or 'crawl'

        return KatanaEndpoint(
            url=url,
            method=method.upper() if method else 'GET',
            status_code=int(status_code) if status_code else None,
            content_type=content_type,
            content_length=int(content_length) if content_length else None,
            depth=depth if isinstance(depth, int) else 0,
            source=str(source)
        )
    except Exception as e:
        logger.debug(f"Error parsing Katana line: {e}")
        return None


def check_katana_available() -> bool:
    """Check if Katana is available on the system."""
    try:
        result = subprocess.run(
            [settings.KATANA_PATH or 'katana', '-version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return False
