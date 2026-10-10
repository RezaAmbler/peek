"""Nikto web server scanner integration."""
import json
import logging
from typing import List, Dict, Any, Optional

from ..core.validators import validate_target, validate_port, ValidationError
from .base import ToolResult, failure_reason, read_output, run_command, temp_workdir

logger = logging.getLogger(__name__)


def run_nikto(
    target: str,
    port: int = 80,
    timeout: int = 120,
    ssl: bool = False
) -> ToolResult:
    """
    Run Nikto against a web server.

    Args:
        target: IP or hostname
        port: Port number
        timeout: Max execution time in seconds
        ssl: Use SSL/TLS

    Returns:
        ToolResult, unpackable as (success, json_output, error_message).
        A non-zero exit or an empty report is a failure, never a clean scan:
        Nikto writes the host record to the JSON report even when it has no
        findings, so "no output" means it did not test the server.
    """
    # Validate inputs to prevent command injection
    try:
        target = validate_target(target)
        port = validate_port(port)
    except ValidationError as e:
        return ToolResult(False, None, f"Input validation failed: {e}")

    with temp_workdir('nikto_') as workdir:
        output_path = workdir / 'report.json'

        cmd = [
            'nikto',
            '-h', target,
            '-p', str(port),
            '-Format', 'json',
            '-output', str(output_path),
            '-nointeractive',
            '-maxtime', f'{timeout}s',
        ]

        if ssl:
            cmd.append('-ssl')

        logger.info(f"Running Nikto: {' '.join(cmd)}")

        # Buffer beyond nikto's internal -maxtime so it can write its report
        run = run_command(cmd, timeout=timeout + 30)
        raw_json = read_output(output_path)
        has_output = bool(raw_json.strip())

        error = failure_reason("Nikto", run, timeout + 30)
        if error:
            logger.warning(f"Nikto failed for {target}:{port}: {error}")
            return ToolResult.from_command(False, raw_json if has_output else None, error, run)

        if not has_output:
            error = f"Nikto produced no report (no web server found?): {run.diagnostics()}"
            logger.warning(f"{error} [{target}:{port}]")
            return ToolResult.from_command(False, None, error, run)

        hosts = count_nikto_hosts(raw_json)
        if hosts is None:
            return ToolResult.from_command(False, raw_json, "Nikto report is not valid JSON", run)
        if hosts == 0:
            # "[]": Nikto ran but tested no host, which is not a clean result
            error = f"Nikto tested 0 hosts (no web server found?): {run.diagnostics()}"
            return ToolResult.from_command(False, raw_json, error, run)

        logger.info(f"Nikto completed for {target}:{port}")
        return ToolResult.from_command(True, raw_json, None, run)


def _collect_nikto_items(data) -> List[Dict[str, Any]]:
    """Flatten the supported Nikto JSON layouts into a list of finding dicts."""
    if isinstance(data, list):
        items: List[Dict[str, Any]] = []
        for entry in data:
            if isinstance(entry, dict) and isinstance(entry.get('vulnerabilities'), list):
                # Host record (Nikto 2.6.x): findings are nested
                items.extend(entry['vulnerabilities'])
            elif isinstance(entry, dict) and _is_host_record(entry):
                continue  # Host record without findings
            else:
                items.append(entry)  # Legacy: bare list of findings
        return items

    if isinstance(data, dict):
        for key in ('vulnerabilities', 'items'):
            if isinstance(data.get(key), list) and data[key]:
                return data[key]
        # Check if it's nested under a host key
        for key in ('host', 'results', 'scan'):
            nested = data.get(key)
            if isinstance(nested, dict):
                found = nested.get('vulnerabilities') or nested.get('items')
                if isinstance(found, list) and found:
                    return found
    return []


def _is_host_record(entry: Dict[str, Any]) -> bool:
    return 'ip' in entry and 'msg' not in entry and 'id' not in entry


def count_nikto_hosts(raw_json: str) -> Optional[int]:
    """Number of host records in a Nikto report, or None if it is not valid JSON."""
    try:
        data = json.loads(raw_json)
    except (json.JSONDecodeError, TypeError):
        return None
    if isinstance(data, list):
        return len(data)
    return 1 if isinstance(data, dict) and data else 0


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

        # Nikto 2.6.x writes a list of host records:
        #   [{"host": "...", "ip": "...", "port": "...", "vulnerabilities": [...]}]
        # Older releases wrote a single host record, or a bare list of findings.

        vulns = _collect_nikto_items(data)

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
        except Exception as e:
            logger.warning(f"Failed to parse Nikto JSONL fallback: {e}")

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
