"""
Parser for testssl.sh JSON output.

testssl.sh outputs an array of finding objects:
[
    {"id": "SSLv2", "severity": "OK", "finding": "not offered"},
    {"id": "heartbleed", "severity": "OK", "finding": "not vulnerable"},
    {"id": "cert_commonName", "severity": "INFO", "finding": "example.com"},
    ...
]

This parser extracts:
- Protocol support matrix
- Certificate details
- Vulnerability findings
- Cipher analysis
- Server configuration issues
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Severity mapping for testssl.sh findings
SEVERITY_MAP = {
    'CRITICAL': 'critical',
    'HIGH': 'high',
    'MEDIUM': 'medium',
    'LOW': 'low',
    'WARN': 'medium',
    'INFO': 'info',
    'OK': 'ok',
    'DEBUG': 'debug',
}

# Protocol IDs in testssl.sh output
PROTOCOL_IDS = {
    'SSLv2': 'SSLv2',
    'SSLv3': 'SSLv3',
    'TLS1': 'TLS1.0',
    'TLS1_1': 'TLS1.1',
    'TLS1_2': 'TLS1.2',
    'TLS1_3': 'TLS1.3',
}

# Known vulnerability IDs
VULNERABILITY_IDS = [
    'heartbleed',
    'CCS', 'ccs-injection',  # CCS Injection
    'ticketbleed',
    'ROBOT',
    'secure_renego',
    'secure_client_renego',
    'CRIME_TLS',
    'BREACH',
    'POODLE_SSL',
    'fallback_SCSV',
    'SWEET32',
    'FREAK',
    'DROWN',
    'DROWN_hint',
    'LOGJAM',
    'LOGJAM-common_primes',
    'BEAST_CBC_TLS1',
    'BEAST',
    'LUCKY13',
    'winshock',
    'RC4',
]

# Certificate-related IDs
CERT_IDS = {
    'cert_commonName': 'subject',
    'cert_commonName_wo_SNI': 'subject_no_sni',
    'cert_subjectAltName': 'subjectAltNames',
    'cert_notBefore': 'notBefore',
    'cert_notAfter': 'notAfter',
    'cert_caIssuers': 'issuer',
    'cert_trust': 'trust',
    'cert_chain_of_trust': 'chainOfTrust',
    'cert_signatureAlgorithm': 'signatureAlgorithm',
    'cert_keySize': 'keySize',
    'cert_keyUsage': 'keyUsage',
    'cert_extKeyUsage': 'extKeyUsage',
    'cert_serialNumber': 'serialNumber',
    'cert_fingerprintSHA1': 'fingerprintSHA1',
    'cert_fingerprintSHA256': 'fingerprintSHA256',
    'cert_ocspURL': 'ocspUrl',
    'cert_crlDistributionPoints': 'crlDistributionPoints',
    'cert_mustStapleExtension': 'mustStaple',
    'cert_expirationStatus': 'expirationStatus',
    'cert_validityPeriod': 'validityPeriod',
}


def parse_testssl_output(parsed_data: List[Dict]) -> Dict[str, Any]:
    """
    Parse testssl.sh JSON output into structured data.

    Args:
        parsed_data: Parsed JSON array from testssl.sh

    Returns:
        Dict with:
        - protocols: Protocol support dict
        - certificate_info: Certificate details dict
        - vulnerabilities: List of vulnerability findings
        - cipher_findings: Cipher analysis dict
        - server_config: Server configuration issues
        - overall_grade: Computed grade (A+, A, B, C, D, F)
        - connection_failed: bool
        - failure_reason: str if failed
    """
    result = {
        'protocols': {},
        'certificate_info': {},
        'vulnerabilities': [],
        'cipher_findings': {
            'weak': [],
            'preferred': [],
            'forwardSecrecy': None,
            'aead': None,
            'nullCiphers': False,
            'exportCiphers': False,
            'rc4': False,
        },
        'server_config': [],
        'overall_grade': None,
        'connection_failed': False,
        'failure_reason': None,
    }

    if not parsed_data:
        result['connection_failed'] = True
        result['failure_reason'] = 'Empty output'
        return result

    # Flatten nested scanResult if present
    findings = []
    for item in parsed_data:
        if isinstance(item, dict):
            # Check for scanResult array (newer format)
            if 'scanResult' in item:
                for scan_result in item.get('scanResult', []):
                    if isinstance(scan_result, list):
                        findings.extend(scan_result)
                    elif isinstance(scan_result, dict):
                        findings.append(scan_result)
            else:
                findings.append(item)

    # If still no findings, the data might be a flat array
    if not findings:
        findings = parsed_data

    # Process each finding
    for finding in findings:
        if not isinstance(finding, dict):
            continue

        finding_id = finding.get('id', '')
        severity = finding.get('severity', '')
        detail = finding.get('finding', '')
        cve = finding.get('cve', '')

        # Check for fatal errors
        if severity == 'FATAL':
            result['connection_failed'] = True
            result['failure_reason'] = detail
            continue

        # Parse protocol support
        if finding_id in PROTOCOL_IDS:
            proto_name = PROTOCOL_IDS[finding_id]
            # "offered" = enabled, "not offered" = disabled
            enabled = 'offered' in detail.lower() and 'not offered' not in detail.lower()
            result['protocols'][proto_name] = enabled

        # Parse certificate info
        elif finding_id in CERT_IDS:
            cert_key = CERT_IDS[finding_id]
            result['certificate_info'][cert_key] = _parse_cert_value(cert_key, detail, severity)

        # Parse vulnerabilities
        elif any(vuln_id in finding_id.lower() for vuln_id in [v.lower() for v in VULNERABILITY_IDS]):
            is_vulnerable = _is_vulnerable(severity, detail)
            result['vulnerabilities'].append({
                'id': finding_id,
                'severity': SEVERITY_MAP.get(severity, 'unknown'),
                'vulnerable': is_vulnerable,
                'detail': detail,
                'cve': cve if cve else None,
            })

        # Parse cipher findings
        elif 'cipher' in finding_id.lower() or finding_id.startswith('cipherorder_'):
            _parse_cipher_finding(result['cipher_findings'], finding_id, severity, detail)

        # Parse server config
        elif finding_id in ['secure_renego', 'compression', 'fallback_SCSV', 'HSTS', 'HPKP', 'server_banner', 'application_banner']:
            status = 'ok' if severity in ['OK', 'INFO'] else 'vulnerable'
            result['server_config'].append({
                'id': finding_id,
                'status': status,
                'severity': SEVERITY_MAP.get(severity, 'unknown'),
                'detail': detail,
            })

        # Parse forward secrecy
        elif 'FS' in finding_id or 'forward' in finding_id.lower():
            if 'offered' in detail.lower():
                result['cipher_findings']['forwardSecrecy'] = True
            elif 'not offered' in detail.lower():
                result['cipher_findings']['forwardSecrecy'] = False

    # Compute overall grade
    result['overall_grade'] = _calculate_grade(result)

    # Parse days until expiry from cert info
    _extract_cert_expiry(result['certificate_info'])

    return result


def _parse_cert_value(key: str, detail: str, severity: str) -> Any:
    """Parse certificate field value based on key type."""
    if key in ['notBefore', 'notAfter']:
        # Date string
        return detail
    elif key == 'keySize':
        # Extract numeric key size
        try:
            # Format: "RSA 2048 bits" or "EC 256 bits (curve P-256)"
            parts = detail.split()
            for i, part in enumerate(parts):
                if part.isdigit():
                    return int(part)
        except (ValueError, IndexError):
            pass
        return detail
    elif key == 'trust':
        # Trust status
        return severity == 'OK'
    elif key == 'expirationStatus':
        # Check if expired
        return 'expired' in detail.lower()
    elif key == 'mustStaple':
        return detail.lower() not in ['--', 'no', 'not set']
    else:
        return detail


def _is_vulnerable(severity: str, detail: str) -> bool:
    """Determine if a finding indicates vulnerability."""
    if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'WARN']:
        return True
    if severity == 'LOW' and 'vulnerable' in detail.lower():
        return True
    if 'vulnerable' in detail.lower() and 'not vulnerable' not in detail.lower():
        return True
    return False


def _parse_cipher_finding(cipher_findings: Dict, finding_id: str, severity: str, detail: str):
    """Parse cipher-related finding."""
    # Check for weak cipher indicators
    if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'WARN']:
        if 'cipher' in finding_id.lower():
            cipher_findings['weak'].append({
                'name': finding_id,
                'detail': detail,
                'grade': SEVERITY_MAP.get(severity, 'unknown'),
            })

    # Check for NULL ciphers
    if 'null' in detail.lower() and 'offered' in detail.lower():
        cipher_findings['nullCiphers'] = True

    # Check for EXPORT ciphers
    if 'export' in detail.lower() and 'offered' in detail.lower():
        cipher_findings['exportCiphers'] = True

    # Check for RC4
    if 'rc4' in detail.lower() and 'offered' in detail.lower():
        cipher_findings['rc4'] = True

    # Check for AEAD
    if 'aead' in finding_id.lower() or 'gcm' in detail.lower():
        if 'offered' in detail.lower() and 'not offered' not in detail.lower():
            cipher_findings['aead'] = True


def _extract_cert_expiry(cert_info: Dict):
    """Extract days until certificate expiry."""
    not_after = cert_info.get('notAfter')
    if not_after and isinstance(not_after, str):
        try:
            # Common formats: "2024-04-01 12:00" or "Apr  1 12:00:00 2024 GMT"
            for fmt in ['%Y-%m-%d %H:%M', '%b %d %H:%M:%S %Y %Z', '%Y-%m-%d']:
                try:
                    expiry_date = datetime.strptime(not_after.strip(), fmt)
                    days_until = (expiry_date - datetime.utcnow()).days
                    cert_info['daysUntilExpiry'] = days_until
                    cert_info['expired'] = days_until < 0
                    break
                except ValueError:
                    continue
        except Exception:
            pass


def _calculate_grade(result: Dict) -> str:
    """
    Calculate overall TLS grade based on findings.

    Grading:
    - F: Critical vulnerability or SSLv2/SSLv3 enabled
    - D: High severity issues
    - C: Medium severity issues (multiple)
    - B: Medium severity issues (few)
    - A: Low/Info issues only
    - A+: No issues
    """
    protocols = result.get('protocols', {})
    vulns = result.get('vulnerabilities', [])
    cipher_findings = result.get('cipher_findings', {})

    # Automatic F grade conditions
    if protocols.get('SSLv2') or protocols.get('SSLv3'):
        return 'F'

    # Check for critical vulnerabilities
    critical_vulns = [v for v in vulns if v.get('vulnerable') and v.get('severity') == 'critical']
    if critical_vulns:
        return 'F'

    # Check cipher issues
    if cipher_findings.get('nullCiphers') or cipher_findings.get('exportCiphers'):
        return 'F'

    # High severity vulnerabilities
    high_vulns = [v for v in vulns if v.get('vulnerable') and v.get('severity') == 'high']
    if len(high_vulns) >= 2:
        return 'D'
    if high_vulns:
        return 'C'

    # Medium severity
    medium_vulns = [v for v in vulns if v.get('vulnerable') and v.get('severity') == 'medium']
    if len(medium_vulns) >= 3:
        return 'C'
    if len(medium_vulns) >= 1:
        return 'B'

    # Check for deprecated protocols
    if protocols.get('TLS1.0') or protocols.get('TLS1.1'):
        return 'B'

    # Low severity only
    low_vulns = [v for v in vulns if v.get('vulnerable') and v.get('severity') == 'low']
    if low_vulns:
        return 'A'

    # No issues
    return 'A+'


def analyze_testssl_security(parsed_result: Dict) -> List[Dict]:
    """
    Generate human-readable security findings from parsed testssl.sh output.

    Returns list of findings:
    [
        {"severity": "critical", "finding": "SSLv3 enabled", "detail": "..."},
        {"severity": "high", "finding": "TLSv1.0 enabled", "detail": "..."},
        ...
    ]
    """
    findings = []
    protocols = parsed_result.get('protocols', {})
    vulns = parsed_result.get('vulnerabilities', [])
    cipher_findings = parsed_result.get('cipher_findings', {})
    cert_info = parsed_result.get('certificate_info', {})

    # Protocol findings
    if protocols.get('SSLv2'):
        findings.append({
            'severity': 'critical',
            'finding': 'SSLv2 enabled',
            'detail': 'SSLv2 is obsolete and has known vulnerabilities. Disable immediately.',
        })

    if protocols.get('SSLv3'):
        findings.append({
            'severity': 'critical',
            'finding': 'SSLv3 enabled',
            'detail': 'SSLv3 is vulnerable to POODLE attack. Disable immediately.',
        })

    if protocols.get('TLS1.0'):
        findings.append({
            'severity': 'high',
            'finding': 'TLSv1.0 enabled',
            'detail': 'TLSv1.0 is deprecated. Disable when possible.',
        })

    if protocols.get('TLS1.1'):
        findings.append({
            'severity': 'medium',
            'finding': 'TLSv1.1 enabled',
            'detail': 'TLSv1.1 is deprecated. Consider disabling.',
        })

    if not protocols.get('TLS1.2') and not protocols.get('TLS1.3'):
        findings.append({
            'severity': 'critical',
            'finding': 'No modern TLS versions enabled',
            'detail': 'Neither TLSv1.2 nor TLSv1.3 is enabled.',
        })

    # Vulnerability findings
    for vuln in vulns:
        if vuln.get('vulnerable'):
            findings.append({
                'severity': vuln.get('severity', 'unknown'),
                'finding': vuln.get('id', 'Unknown vulnerability'),
                'detail': vuln.get('detail', ''),
                'cve': vuln.get('cve'),
            })

    # Cipher findings
    if cipher_findings.get('nullCiphers'):
        findings.append({
            'severity': 'critical',
            'finding': 'NULL ciphers accepted',
            'detail': 'NULL ciphers provide no encryption.',
        })

    if cipher_findings.get('exportCiphers'):
        findings.append({
            'severity': 'critical',
            'finding': 'EXPORT ciphers accepted',
            'detail': 'EXPORT ciphers are intentionally weak.',
        })

    if cipher_findings.get('rc4'):
        findings.append({
            'severity': 'high',
            'finding': 'RC4 cipher accepted',
            'detail': 'RC4 has known biases and should be disabled.',
        })

    if cipher_findings.get('forwardSecrecy') is False:
        findings.append({
            'severity': 'medium',
            'finding': 'No forward secrecy',
            'detail': 'Server does not support forward secrecy ciphers.',
        })

    # Certificate findings
    if cert_info.get('expired'):
        findings.append({
            'severity': 'critical',
            'finding': 'Certificate expired',
            'detail': 'The server certificate has expired.',
        })

    days_until_expiry = cert_info.get('daysUntilExpiry')
    if days_until_expiry is not None and 0 < days_until_expiry <= 30:
        findings.append({
            'severity': 'high' if days_until_expiry <= 7 else 'medium',
            'finding': f'Certificate expires in {days_until_expiry} days',
            'detail': 'Certificate is expiring soon. Renew it.',
        })

    return findings
