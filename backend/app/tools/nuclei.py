import subprocess
import json
import tempfile
from pathlib import Path
from typing import Tuple, List, Optional
from ..core.config import settings

def run_nuclei(
    target_url: str,
    severity: str = "critical,high,medium",
    templates: Optional[str] = None,
    timeout: int = 300
) -> Tuple[bool, str, Optional[str]]:
    """
    Execute Nuclei vulnerability scanner.

    Args:
        target_url: Target URL (e.g., "http://example.com" or "https://192.168.1.1:8443")
        severity: Comma-separated severity levels (critical, high, medium, low, info)
        templates: Path to custom templates directory (optional)
        timeout: Max execution time in seconds

    Returns:
        (success: bool, raw_jsonl: str, error: Optional[str])
    """
    # Create temp file for output
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        output_path = Path(f.name)

    try:
        # Build command
        cmd = [
            settings.NUCLEI_PATH or 'nuclei',
            '-target', target_url,
            '-severity', severity,
            '-json',
            '-output', str(output_path),
            '-silent',  # Suppress banner
            '-no-color',
            '-no-interactsh',  # Disable interactsh for faster scans
        ]

        # Add custom templates if specified
        if templates:
            cmd.extend(['-templates', templates])

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
    for line in raw_jsonl.strip().split('\n'):
        if not line.strip():
            continue

        try:
            vuln = json.loads(line)

            # Extract info section
            info = vuln.get('info', {})

            # Parse host and port from matched-at URL
            matched_at = vuln.get('matched-at', '')
            host = vuln.get('host', '')

            # Try to extract port from URL
            port = None
            if ':' in matched_at and not matched_at.startswith('https://'):
                # Format: http://example.com:8080/path
                try:
                    port_part = matched_at.split(':')[2].split('/')[0]
                    port = int(port_part)
                except:
                    pass
            elif matched_at.startswith('https://') and ':' in matched_at:
                # Format: https://example.com:8443/path
                try:
                    port_part = matched_at.split(':')[2].split('/')[0]
                    port = int(port_part)
                except:
                    port = 443
            elif matched_at.startswith('https://'):
                port = 443
            elif matched_at.startswith('http://'):
                port = 80

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
            # Skip malformed lines
            continue

    return vulnerabilities
