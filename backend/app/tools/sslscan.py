"""
sslscan tool wrapper for SSL/TLS security analysis.

Analyzes:
- Protocol versions (SSLv2/3, TLSv1.0-1.3)
- Cipher suites and security ratings
- Certificate details
- Known vulnerabilities (Heartbleed, etc.)
"""
import xml.etree.ElementTree as ET
from typing import List, Optional, Dict, Any
from datetime import datetime
from ..core.config import settings
from ..core.validators import validate_target, validate_port, ValidationError
from .base import ToolResult, failure_reason, read_output, run_command, temp_workdir


# Default sslscan path
SSLSCAN_PATH = getattr(settings, 'SSLSCAN_PATH', 'sslscan')


def run_sslscan(
    ip: str,
    port: int,
    timeout: int = 60,
    connect_timeout: int = 10
) -> ToolResult:
    """
    Execute sslscan against a single SSL/TLS endpoint.

    Args:
        ip: Target IP address
        port: Port number
        timeout: Max execution time in seconds
        connect_timeout: Connection timeout in seconds

    Returns:
        ToolResult, unpackable as (success: bool, raw_xml: str, error: Optional[str])
    """
    # Validate inputs to prevent command/argument injection
    try:
        ip = validate_target(ip)
        port = validate_port(port)
        connect_timeout = int(connect_timeout)
    except (ValidationError, TypeError, ValueError) as e:
        return ToolResult(False, "", f"Input validation failed: {e}")

    with temp_workdir('sslscan_') as workdir:
        output_path = workdir / 'sslscan.xml'

        cmd = [
            SSLSCAN_PATH,
            f'--xml={output_path}',
            f'--connect-timeout={connect_timeout}',
            '--no-colour',
            f'{ip}:{port}'
        ]

        run = run_command(cmd, timeout=timeout)
        raw_xml = read_output(output_path)

        error = failure_reason("sslscan", run, timeout)
        if error:
            return ToolResult.from_command(False, raw_xml if raw_xml.strip() else "", error, run)

        if not raw_xml.strip():
            return ToolResult.from_command(
                False, "", f"sslscan produced empty output: {run.diagnostics()}", run)

        # Check for connection errors in output
        if 'Failed to connect' in run.stdout or 'Failed to connect' in run.stderr:
            return ToolResult.from_command(False, raw_xml, "Connection failed", run)

        return ToolResult.from_command(True, raw_xml, None, run)


def parse_sslscan_output(raw_xml: str) -> Dict[str, Any]:
    """
    Parse sslscan XML output into structured data.

    Returns dict matching SslScanResult model fields:
    {
        "sslv2_enabled": False,
        "sslv3_enabled": False,
        "tlsv10_enabled": False,
        "tlsv11_enabled": False,
        "tlsv12_enabled": True,
        "tlsv13_enabled": True,
        "fallback_scsv_supported": True,
        "secure_renegotiation": False,
        "compression_supported": False,
        "heartbleed_vulnerable": False,
        "ciphers": [...],
        "key_exchange_groups": [...],
        "cert_subject": "example.com",
        "cert_issuer": "Let's Encrypt",
        ...
    }
    """
    try:
        root = ET.fromstring(raw_xml)
        result = {
            'sslv2_enabled': False,
            'sslv3_enabled': False,
            'tlsv10_enabled': False,
            'tlsv11_enabled': False,
            'tlsv12_enabled': False,
            'tlsv13_enabled': False,
            'fallback_scsv_supported': None,
            'secure_renegotiation': None,
            'compression_supported': None,
            'heartbleed_vulnerable': False,
            'ciphers': [],
            'key_exchange_groups': [],
            'cert_subject': None,
            'cert_issuer': None,
            'cert_altnames': None,
            'cert_not_before': None,
            'cert_not_after': None,
            'cert_expired': None,
            'cert_self_signed': None,
            'cert_signature_algorithm': None,
            'cert_key_type': None,
            'cert_key_bits': None,
            'connection_failed': False,
            'failure_reason': None
        }

        # Find ssltest element
        ssltest = root.find('ssltest')
        if ssltest is None:
            result['connection_failed'] = True
            result['failure_reason'] = 'No ssltest element in output'
            return result

        # Parse protocols
        for protocol in ssltest.findall('protocol'):
            ptype = protocol.get('type', '')
            version = protocol.get('version', '')
            enabled = protocol.get('enabled') == '1'

            if ptype == 'ssl':
                if version == '2':
                    result['sslv2_enabled'] = enabled
                elif version == '3':
                    result['sslv3_enabled'] = enabled
            elif ptype == 'tls':
                if version == '1.0':
                    result['tlsv10_enabled'] = enabled
                elif version == '1.1':
                    result['tlsv11_enabled'] = enabled
                elif version == '1.2':
                    result['tlsv12_enabled'] = enabled
                elif version == '1.3':
                    result['tlsv13_enabled'] = enabled

        # Parse fallback SCSV
        fallback = ssltest.find('fallback')
        if fallback is not None:
            result['fallback_scsv_supported'] = fallback.get('supported') == '1'

        # Parse renegotiation
        reneg = ssltest.find('renegotiation')
        if reneg is not None:
            result['secure_renegotiation'] = reneg.get('secure') == '1'

        # Parse compression (if present)
        compression = ssltest.find('compression')
        if compression is not None:
            result['compression_supported'] = compression.get('supported') == '1'

        # Parse heartbleed
        for heartbleed in ssltest.findall('heartbleed'):
            if heartbleed.get('vulnerable') == '1':
                result['heartbleed_vulnerable'] = True
                break

        # Parse ciphers
        ciphers = []
        for cipher in ssltest.findall('cipher'):
            cipher_info = {
                'status': cipher.get('status'),  # preferred, accepted
                'sslversion': cipher.get('sslversion'),
                'bits': int(cipher.get('bits', 0)),
                'cipher': cipher.get('cipher'),
                'strength': cipher.get('strength'),  # strong, weak, etc.
            }
            # Optional fields
            if cipher.get('curve'):
                cipher_info['curve'] = cipher.get('curve')
            if cipher.get('ecdhebits'):
                cipher_info['ecdhebits'] = int(cipher.get('ecdhebits'))
            if cipher.get('dhebits'):
                cipher_info['dhebits'] = int(cipher.get('dhebits'))
            ciphers.append(cipher_info)
        result['ciphers'] = ciphers

        # Parse key exchange groups
        groups = []
        for group in ssltest.findall('group'):
            groups.append({
                'sslversion': group.get('sslversion'),
                'bits': int(group.get('bits', 0)),
                'name': group.get('name'),
            })
        result['key_exchange_groups'] = groups

        # Parse certificates
        certs = ssltest.find('certificates')
        if certs is not None:
            # Get the first (leaf) certificate
            cert = certs.find('certificate')
            if cert is not None:
                result['cert_signature_algorithm'] = _get_text(cert, 'signature-algorithm')
                result['cert_subject'] = _get_cdata(cert, 'subject')
                result['cert_issuer'] = _get_cdata(cert, 'issuer')
                result['cert_altnames'] = _get_cdata(cert, 'altnames')
                result['cert_not_before'] = _get_text(cert, 'not-valid-before')
                result['cert_not_after'] = _get_text(cert, 'not-valid-after')
                result['cert_expired'] = _get_bool(cert, 'expired')
                result['cert_self_signed'] = _get_bool(cert, 'self-signed')

                # Public key info
                pk = cert.find('pk')
                if pk is not None:
                    result['cert_key_type'] = pk.get('type')
                    bits = pk.get('bits')
                    if bits:
                        result['cert_key_bits'] = int(bits)

        return result

    except ET.ParseError as e:
        return {
            'connection_failed': True,
            'failure_reason': f'Invalid XML: {str(e)}'
        }


def _get_text(parent, tag: str) -> Optional[str]:
    """Get text content of a child element."""
    elem = parent.find(tag)
    return elem.text.strip() if elem is not None and elem.text else None


def _get_cdata(parent, tag: str) -> Optional[str]:
    """Get text content (including CDATA) of a child element."""
    elem = parent.find(tag)
    if elem is not None and elem.text:
        return elem.text.strip()
    return None


def _get_bool(parent, tag: str) -> Optional[bool]:
    """Get boolean value from element text (true/false)."""
    text = _get_text(parent, tag)
    if text is None:
        return None
    return text.lower() == 'true'


def analyze_ssl_security(parsed_result: Dict) -> List[Dict]:
    """
    Analyze parsed sslscan results and generate security findings.

    Returns list of findings:
    [
        {"severity": "critical", "finding": "SSLv3 enabled", "detail": "..."},
        {"severity": "high", "finding": "TLSv1.0 enabled", "detail": "..."}
    ]
    """
    findings = []

    # Protocol findings
    if parsed_result.get('sslv2_enabled'):
        findings.append({
            'severity': 'critical',
            'finding': 'SSLv2 enabled',
            'detail': 'SSLv2 is obsolete and has known vulnerabilities. Disable immediately.'
        })

    if parsed_result.get('sslv3_enabled'):
        findings.append({
            'severity': 'critical',
            'finding': 'SSLv3 enabled',
            'detail': 'SSLv3 is vulnerable to POODLE attack. Disable immediately.'
        })

    if parsed_result.get('tlsv10_enabled'):
        findings.append({
            'severity': 'high',
            'finding': 'TLSv1.0 enabled',
            'detail': 'TLSv1.0 is deprecated and has known weaknesses. Disable when possible.'
        })

    if parsed_result.get('tlsv11_enabled'):
        findings.append({
            'severity': 'medium',
            'finding': 'TLSv1.1 enabled',
            'detail': 'TLSv1.1 is deprecated. Consider disabling.'
        })

    if not parsed_result.get('tlsv12_enabled') and not parsed_result.get('tlsv13_enabled'):
        findings.append({
            'severity': 'critical',
            'finding': 'No modern TLS versions enabled',
            'detail': 'Neither TLSv1.2 nor TLSv1.3 is enabled. Server only supports deprecated protocols.'
        })

    # Vulnerability findings
    if parsed_result.get('heartbleed_vulnerable'):
        findings.append({
            'severity': 'critical',
            'finding': 'Heartbleed vulnerability',
            'detail': 'Server is vulnerable to Heartbleed (CVE-2014-0160). Patch immediately.'
        })

    # Renegotiation
    if parsed_result.get('secure_renegotiation') is False:
        findings.append({
            'severity': 'high',
            'finding': 'Insecure renegotiation',
            'detail': 'Secure renegotiation is not supported.'
        })

    # Fallback SCSV
    if parsed_result.get('fallback_scsv_supported') is False:
        findings.append({
            'severity': 'medium',
            'finding': 'TLS Fallback SCSV not supported',
            'detail': 'Server does not support TLS_FALLBACK_SCSV, which protects against downgrade attacks.'
        })

    # Compression
    if parsed_result.get('compression_supported'):
        findings.append({
            'severity': 'medium',
            'finding': 'TLS compression enabled',
            'detail': 'TLS compression is vulnerable to CRIME attack. Disable compression.'
        })

    # Cipher findings
    for cipher in parsed_result.get('ciphers', []):
        cipher_name = cipher.get('cipher', '')
        strength = cipher.get('strength', '')

        if 'NULL' in cipher_name:
            findings.append({
                'severity': 'critical',
                'finding': f'NULL cipher: {cipher_name}',
                'detail': 'NULL ciphers provide no encryption.'
            })
        elif 'EXPORT' in cipher_name:
            findings.append({
                'severity': 'critical',
                'finding': f'EXPORT cipher: {cipher_name}',
                'detail': 'EXPORT ciphers are intentionally weak.'
            })
        elif 'DES' in cipher_name and '3DES' not in cipher_name:
            findings.append({
                'severity': 'critical',
                'finding': f'DES cipher: {cipher_name}',
                'detail': 'DES is obsolete with only 56-bit effective key strength.'
            })
        elif 'RC4' in cipher_name:
            findings.append({
                'severity': 'high',
                'finding': f'RC4 cipher: {cipher_name}',
                'detail': 'RC4 has known biases and should be disabled.'
            })
        elif 'ANON' in cipher_name:
            findings.append({
                'severity': 'critical',
                'finding': f'Anonymous cipher: {cipher_name}',
                'detail': 'Anonymous ciphers provide no authentication.'
            })
        elif strength == 'weak':
            findings.append({
                'severity': 'medium',
                'finding': f'Weak cipher: {cipher_name}',
                'detail': f'Cipher is considered weak.'
            })

    # Certificate findings
    if parsed_result.get('cert_expired'):
        findings.append({
            'severity': 'critical',
            'finding': 'Certificate expired',
            'detail': 'The server certificate has expired.'
        })

    if parsed_result.get('cert_self_signed'):
        findings.append({
            'severity': 'medium',
            'finding': 'Self-signed certificate',
            'detail': 'Certificate is self-signed and will not be trusted by clients.'
        })

    cert_key_bits = parsed_result.get('cert_key_bits')
    cert_key_type = parsed_result.get('cert_key_type', 'RSA')
    if cert_key_bits:
        if cert_key_type == 'RSA' and cert_key_bits < 2048:
            findings.append({
                'severity': 'high',
                'finding': f'Weak RSA key ({cert_key_bits} bits)',
                'detail': 'RSA keys should be at least 2048 bits.'
            })

    sig_algo = parsed_result.get('cert_signature_algorithm', '')
    if 'md5' in sig_algo.lower():
        findings.append({
            'severity': 'high',
            'finding': 'MD5 signature algorithm',
            'detail': 'Certificate uses weak MD5 signature algorithm.'
        })
    elif 'sha1' in sig_algo.lower() and 'sha1WithRSA' in sig_algo:
        findings.append({
            'severity': 'medium',
            'finding': 'SHA-1 signature algorithm',
            'detail': 'Certificate uses deprecated SHA-1 signature algorithm.'
        })

    return findings


def calculate_ssl_grade(findings: List[Dict]) -> str:
    """
    Calculate an overall SSL/TLS grade based on findings.

    Returns: A+, A, B, C, D, or F
    """
    if not findings:
        return 'A+'

    severities = [f['severity'] for f in findings]

    if 'critical' in severities:
        return 'F'
    elif severities.count('high') >= 2:
        return 'D'
    elif 'high' in severities:
        return 'C'
    elif severities.count('medium') >= 2:
        return 'B'
    elif 'medium' in severities or 'low' in severities:
        return 'A'
    else:
        return 'A+'
