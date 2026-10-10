import json
import logging
from pathlib import Path
from typing import List, Optional
from ..core.config import settings
from ..core.validators import SHELL_METACHARACTERS, ValidationError, validate_nuclei_template_paths
from .base import ToolResult, failure_reason, read_output, run_command, temp_workdir

logger = logging.getLogger(__name__)

def templates_directory() -> Path:
    """Directory nuclei loads its templates from ($HOME/nuclei-templates unless overridden)."""
    configured = settings.NUCLEI_TEMPLATES_DIR
    return Path(configured).expanduser() if configured else Path.home() / 'nuclei-templates'


def resolve_template_paths(templates: str) -> List[str]:
    """Resolve a config's template selection to absolute paths inside the templates directory.

    The value comes from a user-editable scan config. Templates can execute code
    and send arbitrary requests, so only files/directories that really live
    under the installed template set are passed to nuclei - never an arbitrary
    local path (symlinks are resolved first) or a URL.
    """
    cleaned = validate_nuclei_template_paths(templates)
    if not cleaned:
        return []
    base = templates_directory().resolve()
    resolved = []
    for relative in cleaned.split(','):
        candidate = (base / relative).resolve()
        if candidate != base and base not in candidate.parents:
            raise ValidationError(f"template path escapes the templates directory: {relative!r}")
        if not candidate.exists():
            raise ValidationError(f"template path not found in {base}: {relative!r}")
        resolved.append(str(candidate))
    return resolved


def _build_nuclei_command(
    output_path: Path,
    severity: str,
    rate_limit: int,
    tags: Optional[List[str]],
    exclude_templates: Optional[List[str]],
) -> List[str]:
    """Flags shared by target-mode and list-mode (verified against nuclei v3.11.1)."""
    cmd = [
        settings.NUCLEI_PATH or 'nuclei',
        '-severity', severity,
        '-jsonl-export', str(output_path),  # Export results to JSONL file
        '-silent',  # Suppress banner
        '-no-color',
        '-no-interactsh',  # Disable interactsh for faster scans
        '-omit-raw',  # Strip raw request/response to reduce output size
        '-rate-limit', str(rate_limit),
        # The image ships a pinned template set; without this nuclei would
        # check for and install newer templates on every run.
        '-disable-update-check',
    ]

    if tags:
        cmd.extend(['-tags', ','.join(tags)])

    if exclude_templates:
        for exclusion in exclude_templates:
            cmd.extend(['-exclude-templates', exclusion])

    return cmd


def _execute_nuclei(cmd: List[str], output_path: Path, timeout: int, label: str) -> ToolResult:
    """Run nuclei and decide success from the exit code, not from the output file.

    nuclei exits 0 when the scan ran (with or without findings) and non-zero on
    any fatal error (unknown flag, no templates loaded, bad input). The JSONL
    export is only written when nuclei shuts down cleanly, so an empty or
    missing file proves nothing by itself.
    """
    run = run_command(cmd, timeout=timeout)
    raw_jsonl = read_output(output_path)

    error = failure_reason(label, run, timeout)
    if error:
        logger.warning(f"{label} failed: {error}")
        return ToolResult.from_command(False, raw_jsonl if raw_jsonl.strip() else "", error, run)

    if not raw_jsonl.strip():
        # Clean exit and no results = no vulnerabilities found
        raw_jsonl = ""

    return ToolResult.from_command(True, raw_jsonl, None, run)


def run_nuclei(
    target_url: str = None,
    target: str = None,
    severity: str = "critical,high,medium",
    templates: Optional[str] = None,
    tags: Optional[List[str]] = None,
    timeout: int = 300,
    rate_limit: int = 150,
    exclude_templates: Optional[List[str]] = None
) -> ToolResult:
    """
    Execute Nuclei vulnerability scanner.

    Args:
        target_url: Target URL (deprecated, use 'target')
        target: Target URL or host:port for network services
        severity: Comma-separated severity levels (critical, high, medium, low, info)
        templates: Path to custom templates directory (optional)
        tags: List of nuclei template tags to filter (e.g., ['ssh', 'network'])
        timeout: Max execution time in seconds
        rate_limit: Max requests per second
        exclude_templates: List of template patterns to exclude

    Returns:
        ToolResult, unpackable as (success: bool, raw_jsonl: str, error: Optional[str]).
        A non-zero exit, timeout or missing binary is success=False - never an
        empty "clean" result.
    """
    # Support both 'target' and legacy 'target_url' parameter
    actual_target = target or target_url
    if not actual_target:
        return ToolResult(False, "", "No target specified")

    # Validate target to prevent command injection
    # For nuclei, target can be URL (http://...) or host:port (192.168.1.1:22)
    # We check for shell metacharacters in the raw target
    dangerous_chars = SHELL_METACHARACTERS.intersection(actual_target)
    if dangerous_chars or actual_target.startswith('-'):
        return ToolResult(False, "", f"Invalid target: contains shell metacharacters {dangerous_chars or '-'}")

    with temp_workdir('nuclei_') as workdir:
        output_path = workdir / 'results.jsonl'  # does not exist until nuclei writes it

        cmd = _build_nuclei_command(output_path, severity, rate_limit, tags, exclude_templates)
        cmd.extend(['-target', actual_target])

        # Add custom templates if specified (templates override tags)
        if templates:
            try:
                resolved = resolve_template_paths(templates)
            except ValidationError as e:
                return ToolResult(False, "", f"Invalid nuclei_templates: {e}")
            cmd.extend(['-templates', ','.join(resolved)])

        return _execute_nuclei(cmd, output_path, timeout, "Nuclei")


def run_nuclei_list(
    urls_file: str,
    severity: str = "critical,high,medium",
    tags: Optional[List[str]] = None,
    timeout: int = 600,
    rate_limit: int = 50,
    exclude_templates: Optional[List[str]] = None
) -> ToolResult:
    """
    Execute Nuclei against a list of URLs (endpoint mode).

    Uses -list flag instead of -target for batch scanning of discovered endpoints.
    Restricts to HTTP-relevant templates for safety.

    Args:
        urls_file: Path to file containing URLs (one per line)
        severity: Comma-separated severity levels
        tags: List of nuclei template tags (defaults to HTTP-relevant)
        timeout: Max execution time in seconds (default 600 for batch)
        rate_limit: Max requests per second (default 50 for safety)
        exclude_templates: List of template patterns to exclude

    Returns:
        ToolResult, unpackable as (success: bool, raw_jsonl: str, error: Optional[str])
    """
    if not urls_file:
        return ToolResult(False, "", "No URLs file specified")

    # Verify file exists
    if not Path(urls_file).exists():
        return ToolResult(False, "", f"URLs file not found: {urls_file}")

    # Default to HTTP-relevant tags if not specified
    if tags is None:
        tags = ['http', 'cve', 'exposure', 'misconfig', 'tech']

    with temp_workdir('nuclei_') as workdir:
        output_path = workdir / 'results.jsonl'

        cmd = _build_nuclei_command(output_path, severity, rate_limit, tags, exclude_templates)
        cmd.extend(['-list', urls_file])

        logger.info(f"Running nuclei list-mode ({Path(urls_file).stat().st_size} bytes input)")

        return _execute_nuclei(cmd, output_path, timeout, "Nuclei list-mode")


def extract_port_from_matched_at(matched_at: str) -> Optional[int]:
    """
    Extract port number from nuclei matched_at field.

    Handles various formats:
    - 203.0.113.10:22 (raw IP:port - network services)
    - http://example.com:8080/path
    - https://example.com:8443/path
    - http://example.com/path (default 80)
    - https://example.com/path (default 443)
    - ssh://203.0.113.10:22
    - tcp://192.168.1.1:3306
    """
    if not matched_at:
        return None

    import re

    # Pattern 1: Raw IP:port (no protocol) - e.g., "203.0.113.10:22"
    # This handles network service scans (SSH, MySQL, etc.)
    raw_ip_port = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$', matched_at)
    if raw_ip_port:
        try:
            return int(raw_ip_port.group(2))
        except ValueError:
            pass

    # Pattern 2: Protocol with port - e.g., "ssh://host:22", "tcp://host:3306"
    proto_port = re.match(r'^[a-z]+://[^:]+:(\d+)', matched_at)
    if proto_port:
        try:
            return int(proto_port.group(1))
        except ValueError:
            pass

    # Pattern 3: HTTP/HTTPS with explicit port
    http_port = re.match(r'^https?://[^/:]+:(\d+)', matched_at)
    if http_port:
        try:
            return int(http_port.group(1))
        except ValueError:
            pass

    # Pattern 4: Default ports for HTTP/HTTPS
    if matched_at.startswith('https://'):
        return 443
    elif matched_at.startswith('http://'):
        return 80

    return None


def parse_nuclei_output(raw_jsonl: str) -> List[dict]:
    """
    Parse Nuclei JSONL output into vulnerability list.

    Input format (one JSON per line):
    {
        "template-id": "CVE-2023-12345",
        "info": {
            "name": "Vulnerability Name",
            "severity": "high",
            "description": "...",
            "reference": ["https://cve.mitre.org/..."],
            "tags": ["cve", "wordpress"]
        },
        "type": "http",
        "host": "http://example.com",
        "matched-at": "http://example.com/admin",
        "extracted-results": ["extracted data"],
        "curl-command": "curl -X GET ...",
        "timestamp": "2024-01-01T12:00:00Z"
    }

    Returns:
    [
        {
            "template_id": "CVE-2023-12345",
            "name": "Vulnerability Name",
            "severity": "high",
            "type": "cve",
            "matched_at": "http://example.com/admin",
            "host": "http://example.com",
            "port": 80,
            "extracted_results": ["extracted data"],
            "curl_command": "curl -X GET ...",
            "description": "...",
            "reference": ["https://..."],
            "tags": ["cve", "wordpress"]
        }
    ]
    """
    if not raw_jsonl.strip():
        return []

    vulnerabilities = []

    # Parse each line as separate JSON
    lines = raw_jsonl.strip().split('\n')
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        try:
            vuln = json.loads(line)

            # Extract info section
            info = vuln.get('info', {})

            # Parse host and port from matched-at URL
            matched_at = vuln.get('matched-at', '')
            host = vuln.get('host', '')

            # Try to extract port from URL using robust parsing
            port = extract_port_from_matched_at(matched_at)

            parsed_vuln = {
                'template_id': vuln.get('template-id', 'unknown'),
                'name': info.get('name', 'Unknown Vulnerability'),
                'severity': info.get('severity', 'info'),
                'type': vuln.get('type', 'http'),
                'matched_at': matched_at,
                'host': host,
                'port': port,
                'extracted_results': vuln.get('extracted-results'),
                'curl_command': vuln.get('curl-command'),
                'description': info.get('description'),
                'reference': info.get('reference'),
                'tags': info.get('tags', [])
            }

            vulnerabilities.append(parsed_vuln)

        except json.JSONDecodeError as e:
            # Log malformed lines with preview for debugging
            line_preview = line[:100] + '...' if len(line) > 100 else line
            logger.warning(f"Nuclei JSONL parse error on line {i}: {e} — preview: {line_preview}")
            continue

    return vulnerabilities
