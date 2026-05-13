# ssh-audit

ssh-audit analyzes SSH server configurations for security issues in Phase 4.

## Phase

| Phase | Purpose |
|-------|---------|
| 4 | SSH security analysis - algorithms, key exchange, vulnerabilities |

## Wrapper Location

`backend/app/tools/ssh_audit.py`

## Parser Location

`backend/app/parsers/ssh_audit_parser.py`

## Function

```python
def run_ssh_audit(
    ip: str,
    port: int = 22,
    timeout: int = 60
) -> Tuple[bool, str, Optional[str]]
```

## Command Pattern

```bash
ssh-audit -j -p <port> <ip>
```

## Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `enable_ssh_audit` | Enable SSH analysis | true |
| `ssh_ports` | Ports to check for SSH | `[22]` |

## Output Format

ssh-audit outputs JSON:

```json
{
    "banner": {
        "raw": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        "protocol": "2.0"
    },
    "kex": [
        {"algorithm": "curve25519-sha256", "notes": {...}},
        {"algorithm": "diffie-hellman-group14-sha256", "notes": {...}}
    ],
    "key": [
        {"algorithm": "ssh-ed25519", "notes": {...}},
        {"algorithm": "ssh-rsa", "notes": {...}}
    ],
    "enc": [
        {"algorithm": "aes256-gcm@openssh.com", "notes": {...}},
        {"algorithm": "aes128-ctr", "notes": {...}}
    ],
    "mac": [
        {"algorithm": "hmac-sha2-512", "notes": {...}}
    ],
    "compression": ["none"],
    "cves": [
        {"name": "CVE-2023-XXXX", "description": "..."}
    ],
    "recommendations": {
        "critical": {"del": {"kex": [...]}},
        "warning": {"chg": {"enc": [...]}}
    }
}
```

Parsed into:

```python
{
    "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
    "ssh_version": "2.0",
    "key_exchange": ["curve25519-sha256", "diffie-hellman-group14-sha256"],
    "host_keys": ["ssh-ed25519", "ssh-rsa"],
    "encryption": ["aes256-gcm@openssh.com", "aes128-ctr"],
    "mac": ["hmac-sha2-512"],
    "compression": ["none"],
    "vulnerabilities": [
        {"severity": "critical", "description": "CVE-2023-XXXX", "cve": "CVE-2023-XXXX"}
    ],
    "recommendations": [
        {"action": "del", "item": "kex: weak-algorithm"}
    ]
}
```

## Database Model

Results stored in `SSHAudit`:

| Field | Type | Description |
|-------|------|-------------|
| `banner` | String | SSH banner |
| `ssh_version` | String | Protocol version |
| `key_exchange` | JSON | KEX algorithms |
| `host_keys` | JSON | Host key algorithms |
| `encryption` | JSON | Cipher algorithms |
| `mac` | JSON | MAC algorithms |
| `compression` | JSON | Compression methods |
| `vulnerabilities` | JSON | CVEs and warnings |
| `recommendations` | JSON | Hardening advice |

## Vulnerability Extraction

The parser extracts vulnerabilities from:

1. **CVE list**: Direct CVE references
2. **Algorithm notes**: Fail/warn messages in algorithm details
3. **Recommendations**: Actions to remove weak algorithms

Severity levels:
- `critical`: CVEs, fail notes
- `warning`: Warn notes

## Error Handling

ssh-audit may output colored error messages instead of JSON:

```
[exception] cannot connect to 1.2.3.4 port 22: timed out
```

The `_extract_ssh_audit_error()` function:
1. Strips ANSI escape codes
2. Matches common error patterns
3. Returns clean error message

## Port Detection

SSH ports are detected during Nmap service detection (Phase 2):
- Service name contains "ssh"
- Typically port 22, but any port with SSH service is scanned

## Security Notes

- Input validation via `validate_target()` and `validate_port()`
- JSON parsing validates output before storing
- Non-zero exit code doesn't indicate failure (issues found = non-zero)

## Related

- [Scan Lifecycle](../scan-lifecycle.md) - Phase 4 details
- [Backend Architecture](../backend.md) - SSHAudit model
