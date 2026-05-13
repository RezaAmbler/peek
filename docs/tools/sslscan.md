# sslscan

sslscan provides quick SSL/TLS security analysis in Phase 7.

## Phase

| Phase | Purpose |
|-------|---------|
| 7 | Quick TLS/SSL cipher and certificate analysis |

## Wrapper Location

`backend/app/tools/sslscan.py`

## Parser Location

Parsing included in `sslscan.py`

## Function

```python
def run_sslscan(
    ip: str,
    port: int,
    timeout: int = 60,
    connect_timeout: int = 10
) -> Tuple[bool, str, Optional[str]]
```

## Command Pattern

```bash
sslscan --xml=output.xml --connect-timeout=10 --no-colour <ip>:<port>
```

## Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `enable_sslscan` | Enable quick TLS analysis | true |

## Analysis Categories

### Protocol Detection
- SSLv2, SSLv3 (critical if enabled)
- TLSv1.0, TLSv1.1 (deprecated)
- TLSv1.2, TLSv1.3 (modern)

### Security Features
- Fallback SCSV support
- Secure renegotiation
- TLS compression (CRIME vulnerability)
- Heartbleed vulnerability

### Cipher Analysis
- NULL ciphers (no encryption)
- EXPORT ciphers (weak)
- DES/3DES ciphers
- RC4 ciphers
- Anonymous ciphers
- Strength ratings

### Certificate Analysis
- Subject and issuer
- Alternative names
- Validity dates
- Expiration status
- Self-signed detection
- Key type and size
- Signature algorithm

## Output Format

sslscan outputs XML which is parsed into:

```python
{
    "sslv2_enabled": False,
    "sslv3_enabled": False,
    "tlsv10_enabled": False,
    "tlsv11_enabled": False,
    "tlsv12_enabled": True,
    "tlsv13_enabled": True,
    "fallback_scsv_supported": True,
    "secure_renegotiation": True,
    "compression_supported": False,
    "heartbleed_vulnerable": False,
    "ciphers": [
        {
            "status": "preferred",
            "sslversion": "TLSv1.3",
            "bits": 256,
            "cipher": "TLS_AES_256_GCM_SHA384",
            "strength": "strong"
        }
    ],
    "key_exchange_groups": [...],
    "cert_subject": "example.com",
    "cert_issuer": "Let's Encrypt",
    "cert_not_after": "2024-12-31",
    "cert_expired": False,
    "cert_self_signed": False,
    "cert_key_type": "RSA",
    "cert_key_bits": 2048
}
```

## Security Grading

The `calculate_ssl_grade()` function assigns grades:

| Grade | Criteria |
|-------|----------|
| A+ | No findings |
| A | Only low/medium findings |
| B | Multiple medium findings |
| C | One high finding |
| D | Multiple high findings |
| F | Any critical finding |

## Finding Severity

| Severity | Examples |
|----------|----------|
| Critical | SSLv2/v3, Heartbleed, NULL/EXPORT ciphers |
| High | TLSv1.0, RC4, insecure renegotiation, expired cert |
| Medium | TLSv1.1, weak ciphers, no fallback SCSV, self-signed |

## Database Model

Results stored in `SslScanResult`:

| Field | Type | Description |
|-------|------|-------------|
| Protocol flags | Boolean | `sslv2_enabled`, `tlsv13_enabled`, etc. |
| Security flags | Boolean | `heartbleed_vulnerable`, etc. |
| `ciphers` | JSON | Cipher suite details |
| Certificate fields | String | Subject, issuer, dates, etc. |
| `connection_failed` | Boolean | Connection status |

## Comparison with testssl.sh

| Feature | sslscan | testssl.sh |
|---------|---------|------------|
| Speed | Fast | Slow |
| Depth | Basic | Comprehensive |
| Output | XML | JSON |
| Phase | 7 | 7.5 |

Use sslscan for quick checks, testssl.sh for deep analysis.

## Related

- [testssl.sh](testssl.md) - Deep TLS analysis
- [Scan Lifecycle](../scan-lifecycle.md) - Phase 7 details
