# testssl.sh

testssl.sh provides comprehensive TLS/SSL security analysis in Phase 7.5.

## Phase

| Phase | Purpose |
|-------|---------|
| 7.5 | Deep TLS analysis with vulnerability checks |

## Wrapper Location

`backend/app/tools/testssl.py`

## Parser Location

`backend/app/parsers/testssl_parser.py`

## Function

```python
def run_testssl(
    host: str,
    port: int,
    timeout: int = 300,
    fast_mode: bool = True,
) -> TestsslOutput
```

**Returns**: `TestsslOutput` dataclass with:
- `success: bool`
- `raw_json: Optional[str]`
- `parsed_data: Optional[Dict[str, Any]]`
- `error: Optional[str]`
- `host: Optional[str]`
- `port: Optional[int]`

## Command Pattern

```bash
testssl --jsonfile=output.json --warnings batch --quiet --sneaky \
        --connect-timeout=10 --openssl-timeout=10 --fast <host>:<port>
```

## Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `enable_testssl` | Enable deep TLS analysis | true |
| `testssl_timeout` | Execution timeout | 300s |

## Analysis Categories

### Protocol Testing
- SSLv2/SSLv3 (deprecated)
- TLSv1.0/1.1 (deprecated)
- TLSv1.2/1.3 (modern)

### Vulnerability Checks
- Heartbleed (CVE-2014-0160)
- POODLE (SSLv3)
- BEAST (TLSv1.0 CBC)
- DROWN (SSLv2 cross-protocol)
- ROBOT (RSA padding oracle)
- FREAK (export ciphers)
- Logjam (DH export)
- Sweet32 (64-bit block ciphers)
- Lucky13 (CBC timing)
- CRIME (compression)
- BREACH (HTTP compression)

### Certificate Analysis
- Chain validation
- Trust path
- Revocation status
- Certificate transparency
- Key usage

### Security Headers
- HSTS (HTTP Strict Transport Security)
- HPKP (HTTP Public Key Pinning)
- Expect-CT

### Forward Secrecy
- ECDHE support
- DHE support
- Key exchange groups

## Output Format

testssl.sh outputs JSON array:

```json
[
    {
        "id": "optimal_proto",
        "severity": "OK",
        "finding": "TLSv1.3"
    },
    {
        "id": "heartbleed",
        "severity": "OK",
        "finding": "not vulnerable"
    },
    {
        "id": "SSLv3",
        "severity": "OK",
        "finding": "not offered"
    },
    {
        "id": "POODLE_SSL",
        "severity": "OK",
        "finding": "not vulnerable"
    }
]
```

## Database Model

Results stored in `TestsslResult`:

| Field | Type | Description |
|-------|------|-------------|
| `raw_json` | Text | Full JSON output |
| `protocol_support` | JSON | Protocol versions |
| `vulnerabilities` | JSON | Vulnerability findings |
| `certificate_info` | JSON | Cert chain details |
| `forward_secrecy` | JSON | FS evaluation |
| `overall_grade` | String | Security grade |

## Fast Mode

The `--fast` flag skips:
- Exhaustive cipher enumeration
- All vulnerability variants
- Extended certificate checks

Use fast mode for regular scans, disable for thorough audits.

## Comparison with sslscan

| Feature | testssl.sh | sslscan |
|---------|------------|---------|
| Speed | Slow (2-5 min) | Fast (10-30 sec) |
| Depth | Comprehensive | Basic |
| Vulnerabilities | 15+ checks | 5 checks |
| Headers | HSTS, HPKP, CT | None |
| Output | JSON | XML |

## Security Notes

- Shell metacharacter validation
- Timeout handling with partial result recovery
- `--sneaky` uses browser-like User-Agent
- `--warnings batch` prevents interactive pauses

## Related

- [sslscan](sslscan.md) - Quick TLS analysis
- [Scan Lifecycle](../scan-lifecycle.md) - Phase 7.5 details
