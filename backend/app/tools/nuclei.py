import subprocess
import json
import tempfile
import logging
from pathlib import Path
from typing import Tuple, List, Optional
from ..core.config import settings
from ..core.validators import validate_target, ValidationError

logger = logging.getLogger(__name__)

def run_nuclei(
    target_url: str = None,
    target: str = None,
    severity: str = "critical,high,medium",
    templates: Optional[str] = None,
    tags: Optional[List[str]] = None,
    timeout: int = 300,
    rate_limit: int = 150,
    exclude_templates: Optional[List[str]] = None
) -> Tuple[bool, str, Optional[str]]:
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
        (success: bool, raw_jsonl: str, error: Optional[str])
    """
    # Support both 'target' and legacy 'target_url' parameter
    actual_target = target or target_url
    if not actual_target:
        return False, "", "No target specified"

    # Validate target to prevent command injection
    # For nuclei, target can be URL (http://...) or host:port (192.168.1.1:22)
    # We check for shell metacharacters in the raw target
    dangerous_chars = set(';&|`$(){}[]<>\\"\'\n\r\t').intersection(actual_target)
    if dangerous_chars:
        return False, "", f"Invalid target: contains shell metacharacters {dangerous_chars}"

    # Create temp file for output
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        output_path = Path(f.name)

    try:
        # Build command
        cmd = [
            settings.NUCLEI_PATH or 'nuclei',
            '-target', actual_target,
            '-severity', severity,
            '-jsonl-export', str(output_path),  # Export results to JSONL file
            '-silent',  # Suppress banner
            '-no-color',
            '-no-interactsh',  # Disable interactsh for faster scans
            '-omit-raw',  # Strip raw request/response to reduce output size
            '-rate-limit', str(rate_limit),
        ]

        # Add tags for service-specific scanning
        if tags:
            cmd.extend(['-tags', ','.join(tags)])

        # Add custom templates if specified (templates override tags)
        if templates:
            cmd.extend(['-templates', templates])

        # Add exclusions if provided
        if exclude_templates:
            for exclusion in exclude_templates:
                cmd.extend(['-exclude-templates', exclusion])

        # Execute
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Check if output file exists
        if not output_path.exists():
            return False, "", f"Nuclei did not create output file. stderr: {result.stderr}"

        # Read raw JSONL output
        raw_jsonl = output_path.read_text()

        if not raw_jsonl.strip():
            # Empty output = no vulnerabilities found (this is success)
            raw_jsonl = ""

        # Nuclei returns 0 even if vulns found
        return True, raw_jsonl, None

    except subprocess.TimeoutExpired:
        return False, "", f"Nuclei timed out after {timeout} seconds"
    except FileNotFoundError:
        return False, "", "nuclei not found. Install from: https://github.com/projectdiscovery/nuclei"
    except Exception as e:
        return False, "", f"Nuclei execution failed: {str(e)}"
    finally:
        # Cleanup temp file
        if output_path.exists():
            output_path.unlink()

def run_nuclei_list(
    urls_file: str,
    severity: str = "critical,high,medium",
    tags: Optional[List[str]] = None,
    timeout: int = 600,
    rate_limit: int = 50,
    exclude_templates: Optional[List[str]] = None
) -> Tuple[bool, str, Optional[str]]:
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
        (success: bool, raw_jsonl: str, error: Optional[str])
    """
    if not urls_file:
        return False, "", "No URLs file specified"

    # Verify file exists
    if not Path(urls_file).exists():
        return False, "", f"URLs file not found: {urls_file}"

    # Default to HTTP-relevant tags if not specified
    if tags is None:
        tags = ['http', 'cve', 'exposure', 'misconfig', 'tech']

    # Create temp file for output
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        output_path = Path(f.name)

    try:
        # Build command
        cmd = [
            settings.NUCLEI_PATH or 'nuclei',
            '-list', urls_file,
            '-severity', severity,
            '-jsonl-export', str(output_path),
            '-silent',
            '-no-color',
            '-no-interactsh',
            '-omit-raw',
            '-rate-limit', str(rate_limit),
        ]

        # Add tags for HTTP-relevant scanning
        if tags:
            cmd.extend(['-tags', ','.join(tags)])

        # Add exclusions if provided
        if exclude_templates:
            for exclusion in exclude_templates:
                cmd.extend(['-exclude-templates', exclusion])

        logger.info(f"Running nuclei list-mode: {' '.join(cmd[:8])}... ({Path(urls_file).stat().st_size} bytes input)")

        # Execute
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Check if output file exists
        if not output_path.exists():
            return False, "", f"Nuclei did not create output file. stderr: {result.stderr}"

        # Read raw JSONL output
        raw_jsonl = output_path.read_text()

        if not raw_jsonl.strip():
            raw_jsonl = ""  # No vulnerabilities found

        return True, raw_jsonl, None

    except subprocess.TimeoutExpired:
        return False, "", f"Nuclei list-mode timed out after {timeout} seconds"
    except FileNotFoundError:
        return False, "", "nuclei not found. Install from: https://github.com/projectdiscovery/nuclei"
    except Exception as e:
        return False, "", f"Nuclei list-mode execution failed: {str(e)}"
    finally:
        # Cleanup temp file
        if output_path.exists():
            output_path.unlink()


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
