"""Katana web crawler integration for endpoint discovery."""
import subprocess
import json
import logging
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from ..core.config import settings
from ..core.validators import SHELL_METACHARACTERS

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


def run_katana(
    target_url: str,
    depth: int = 2,
    timeout: int = 120,
    concurrency: int = 10,
    rate_limit: int = 150,
    max_endpoints: int = 500,
    headless: bool = False,
) -> KatanaOutput:
    """
    Execute Katana web crawler for endpoint discovery.

    Args:
        target_url: Base URL to crawl (e.g., "https://example.com")
        depth: Maximum crawl depth (default 2)
        timeout: Overall timeout in seconds (default 120)
        concurrency: Number of concurrent requests (default 10)
        rate_limit: Max requests per second (default 150)
        max_endpoints: Maximum endpoints to discover (default 500)
        headless: Use headless browser for JS rendering (slower but more complete)

    Returns:
        KatanaOutput with discovered endpoints, raw output, and any errors
    """
    # Validate target to prevent command injection
    dangerous_chars = SHELL_METACHARACTERS.intersection(target_url)
    if dangerous_chars:
        return KatanaOutput(
            success=False,
            error=f"Invalid target: contains shell metacharacters {dangerous_chars}",
            target_url=target_url
        )

    # Create temp file for output
    temp_dir = tempfile.mkdtemp(prefix='katana_')
    output_path = Path(temp_dir) / 'output.jsonl'

    try:
        # Build command
        cmd = [
            'katana',
            '-u', target_url,
            '-jsonl',  # JSON Lines output
            '-silent',
            '-nc',  # No color
            '-d', str(depth),  # Max depth
            '-c', str(concurrency),  # Concurrency
            '-rate-limit', str(rate_limit),  # Requests per second
            '-timeout', str(timeout),  # Overall timeout
            '-field-scope', 'rdn',  # Stay on same root domain (prevent crawling off-target)
            '-o', str(output_path),
        ]

        # Headless mode for JavaScript rendering
        if headless:
            cmd.append('-headless')

        # Automatic form filling (passive, doesn't submit)
        cmd.append('-automatic-form-fill')

        # Store response details (jsonl already includes full output)

        cmd_str = ' '.join(cmd)
        logger.info(f"Running katana: {cmd_str}")

        # Run with timeout buffer
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 30  # Buffer for startup/shutdown
        )

        # Read and parse output
        endpoints = []
        raw_output = ""

        if output_path.exists():
            raw_output = output_path.read_text()
            if raw_output.strip():
                for line in raw_output.strip().split('\n'):
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        endpoint = _parse_katana_line(data)
                        if endpoint:
                            endpoints.append(endpoint)
                            # Check max endpoints limit
                            if len(endpoints) >= max_endpoints:
                                logger.info(f"Reached max_endpoints limit ({max_endpoints})")
                                break
                    except json.JSONDecodeError:
                        logger.debug(f"Skipping non-JSON line: {line[:100]}")
                        continue

        if endpoints:
            logger.info(f"Katana discovered {len(endpoints)} endpoint(s) from {target_url}")
            return KatanaOutput(
                success=True,
                endpoints=endpoints,
                raw_output=raw_output,
                target_url=target_url
            )
        else:
            # Check stderr for errors
            stderr_preview = result.stderr[:500] if result.stderr else ""
            if stderr_preview:
                logger.warning(f"Katana no endpoints, stderr: {stderr_preview}")
            return KatanaOutput(
                success=True,  # Not an error, just no endpoints found
                endpoints=[],
                raw_output=raw_output,
                target_url=target_url
            )

    except subprocess.TimeoutExpired:
        logger.warning(f"Katana timed out after {timeout}s for {target_url}")
        # Return partial results if available
        partial_endpoints = []
        partial_output = ""
        if output_path.exists():
            partial_output = output_path.read_text()
            for line in partial_output.strip().split('\n')[:max_endpoints]:
                if line.strip():
                    try:
                        data = json.loads(line)
                        endpoint = _parse_katana_line(data)
                        if endpoint:
                            partial_endpoints.append(endpoint)
                    except json.JSONDecodeError:
                        continue

        return KatanaOutput(
            success=len(partial_endpoints) > 0,
            endpoints=partial_endpoints,
            raw_output=partial_output,
            error=f"Timeout after {timeout}s (partial results: {len(partial_endpoints)} endpoints)",
            target_url=target_url
        )
    except FileNotFoundError:
        logger.error("Katana not found. Install from: https://github.com/projectdiscovery/katana")
        return KatanaOutput(
            success=False,
            error="Katana not found",
            target_url=target_url
        )
    except Exception as e:
        logger.error(f"Katana error for {target_url}: {e}")
        return KatanaOutput(
            success=False,
            error=str(e),
            target_url=target_url
        )
    finally:
        # Cleanup temp files
        try:
            if output_path.exists():
                output_path.unlink()
            Path(temp_dir).rmdir()
        except Exception:
            pass


def _parse_katana_line(data: dict) -> Optional[KatanaEndpoint]:
    """Parse a single Katana JSONL line into KatanaEndpoint."""
    try:
        # Katana output format varies - handle both request wrapper and flat URL
        url = data.get('request', {}).get('endpoint') or data.get('endpoint') or data.get('url')
        if not url:
            return None

        # Get method from request object or default to GET
        method = data.get('request', {}).get('method') or data.get('method') or 'GET'

        # Get response details if available
        response = data.get('response', {})
        status_code = response.get('status_code') or data.get('status_code')
        content_type = response.get('content_type') or data.get('content_type')
        content_length = response.get('content_length') or data.get('content_length')

        # Get depth and source
        depth = data.get('depth', 0)
        source = data.get('source', 'crawl')

        return KatanaEndpoint(
            url=url,
            method=method.upper() if method else 'GET',
            status_code=int(status_code) if status_code else None,
            content_type=content_type,
            content_length=int(content_length) if content_length else None,
            depth=depth,
            source=source
        )
    except Exception as e:
        logger.debug(f"Error parsing Katana line: {e}")
        return None


def check_katana_available() -> bool:
    """Check if Katana is available on the system."""
    try:
        result = subprocess.run(
            ['katana', '-version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return False
