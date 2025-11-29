"""Nikto web server scanner integration."""
import subprocess
import json
import logging
import tempfile
from pathlib import Path
from typing import Tuple, Optional, List, Dict, Any

logger = logging.getLogger(__name__)


def run_nikto(
    target: str,
    port: int = 80,
    timeout: int = 120,
    ssl: bool = False
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Run Nikto against a web server.

    Args:
        target: IP or hostname
        port: Port number
        timeout: Max execution time in seconds
        ssl: Use SSL/TLS

    Returns:
        Tuple of (success, json_output, error_message)
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        output_path = f.name

    try:
        # Build command
        cmd = [
            'nikto',
            '-h', target,
            '-p', str(port),
            '-Format', 'json',
            '-output', output_path,
            '-nointeractive',
            '-maxtime', f'{timeout}s',
        ]

        if ssl:
            cmd.append('-ssl')

        cmd_str = ' '.join(cmd)
        logger.info(f"Running Nikto: {cmd_str}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 30  # Buffer beyond nikto's internal timeout
        )

        # Read output file
        output_file = Path(output_path)
        if output_file.exists():
            raw_json = output_file.read_text()
            if raw_json.strip():
                logger.info(f"Nikto completed for {target}:{port}")
                return True, raw_json, None
            else:
                logger.warning(f"Nikto produced empty output for {target}:{port}")
                return True, None, "Empty output"
        else:
            stderr_preview = result.stderr[:500] if result.stderr else "no stderr"
            logger.warning(f"Nikto did not produce output file for {target}:{port}: {stderr_preview}")
            return False, None, f"No output file. stderr: {stderr_preview}"

    except subprocess.TimeoutExpired:
        logger.warning(f"Nikto timed out after {timeout}s for {target}:{port}")
        return False, None, f"Timeout after {timeout} seconds"
    except Exception as e:
        logger.error(f"Nikto error for {target}:{port}: {e}")
        return False, None, str(e)
    finally:
        # Cleanup
        Path(output_path).unlink(missing_ok=True)


def parse_nikto_output(raw_json: str) -> List[Dict[str, Any]]:
    """
    Parse Nikto JSON output into normalized findings.

    Args:
        raw_json: Raw JSON string from Nikto

    Returns:
        List of finding dictionaries
    """
    if not raw_json or not raw_json.strip():
        return []

    findings = []
    try:
        data = json.loads(raw_json)

        # Nikto JSON structure: can be a dict with host info or a list
        # Common structure: {"host": "...", "ip": "...", "port": "...", "vulnerabilities": [...]}

        vulns = []
        if isinstance(data, dict):
            # Check for vulnerabilities array
            vulns = data.get('vulnerabilities', [])
            if not vulns:
                # Alternative: items array
                vulns = data.get('items', [])
            if not vulns:
                # Check if it's nested under a host key
                for key in ['host', 'results', 'scan']:
                    if key in data and isinstance(data[key], dict):
                        vulns = data[key].get('vulnerabilities', []) or data[key].get('items', [])
                        if vulns:
                            break
        elif isinstance(data, list):
            # Direct list of findings
            vulns = data

        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue

            finding = {
                'id': str(vuln.get('id', vuln.get('OSVDB', vuln.get('osvdbid', 'unknown')))),
                'name': vuln.get('msg', vuln.get('message', vuln.get('description', 'Unknown finding'))),
                'method': vuln.get('method', 'GET'),
                'url': vuln.get('url', vuln.get('uri', vuln.get('path', '/'))),
                'description': vuln.get('description', vuln.get('msg', '')),
                'references': vuln.get('references', []),
                'osvdb': vuln.get('OSVDB', vuln.get('osvdbid', '')),
            }
            findings.append(finding)

        logger.info(f"Parsed {len(findings)} findings from Nikto output")

    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse Nikto JSON: {e}")
        # Try to parse line by line if it's JSONL
        try:
            for line in raw_json.strip().split('\n'):
                if line.strip():
                    item = json.loads(line)
                    if isinstance(item, dict):
                        findings.append({
                            'id': str(item.get('id', 'unknown')),
                            'name': item.get('msg', item.get('message', 'Unknown')),
                            'method': item.get('method', 'GET'),
                            'url': item.get('url', '/'),
                            'description': item.get('description', ''),
                            'references': [],
                            'osvdb': item.get('OSVDB', ''),
                        })
        except Exception:
            pass

    return findings


def map_nikto_severity(finding: Dict[str, Any]) -> str:
    """
    Map Nikto finding to severity level.

    Nikto doesn't have built-in severity, so we infer from keywords.
    """
    name = finding.get('name', '').lower()
    desc = finding.get('description', '').lower()
    combined = f"{name} {desc}"

    # Critical indicators
    if any(kw in combined for kw in ['remote code', 'rce', 'command injection', 'sql injection', 'arbitrary']):
        return 'critical'

    # High severity
    if any(kw in combined for kw in ['vulnerability', 'exploit', 'bypass', 'authentication', 'xss', 'csrf']):
        return 'high'

    # Medium severity
    if any(kw in combined for kw in ['disclosure', 'leak', 'exposure', 'sensitive', 'backup', 'config']):
        return 'medium'

    # Low severity
    if any(kw in combined for kw in ['header', 'cookie', 'deprecated', 'outdated', 'version']):
        return 'low'

    # Default to info
    return 'info'
