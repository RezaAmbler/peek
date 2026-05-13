# Nikto

Nikto scans web servers for vulnerabilities and misconfigurations in Phase 8.

## Phase

| Phase | Purpose |
|-------|---------|
| 8 | Web server vulnerability scanning |

## Wrapper Location

`backend/app/tools/nikto.py`

## Parser Location

`backend/app/parsers/nikto_parser.py`

## Function

```python
def run_nikto(
    target: str,
    port: int = 80,
    timeout: int = 120,
    ssl: bool = False
) -> Tuple[bool, Optional[str], Optional[str]]
```

## Command Pattern

```bash
nikto -h <target> -p <port> -Format json -output output.json \
      -nointeractive -maxtime <timeout>s [-ssl]
```

## Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `enable_nikto` | Enable web scanning | true |
| `nikto_timeout` | Execution timeout | 120s |

## Scan Coverage

Nikto checks for:

### Server Issues
- Outdated software versions
- Default files and directories
- Dangerous HTTP methods (PUT, DELETE)
- Server misconfigurations

### Known Vulnerabilities
- CVE-indexed vulnerabilities
- OSVDB references
- Common exploits

### Information Disclosure
- Backup files (.bak, .old, .orig)
- Configuration files exposed
- Source code leakage
- Directory listings

### Security Headers
- Missing X-Frame-Options
- Missing X-Content-Type-Options
- Missing Content-Security-Policy

## Output Format

Nikto outputs JSON:

```json
{
    "host": "192.168.1.1",
    "ip": "192.168.1.1",
    "port": "80",
    "vulnerabilities": [
        {
            "id": "999103",
            "OSVDB": "3092",
            "method": "GET",
            "url": "/admin/",
            "msg": "Directory indexing found"
        }
    ]
}
```

Parsed into:

```python
{
    "id": "999103",
    "name": "Directory indexing found",
    "method": "GET",
    "url": "/admin/",
    "description": "Directory indexing found",
    "references": [],
    "osvdb": "3092"
}
```

## Severity Mapping

Nikto doesn't provide severity, so `map_nikto_severity()` infers from keywords:

| Severity | Keywords |
|----------|----------|
| Critical | remote code, rce, command injection, sql injection |
| High | vulnerability, exploit, bypass, authentication, xss, csrf |
| Medium | disclosure, leak, exposure, sensitive, backup, config |
| Low | header, cookie, deprecated, outdated, version |
| Info | Default for unmatched findings |

## Database Integration

Nikto findings create `Vulnerability` records:

| Field | Value |
|-------|-------|
| `template_id` | OSVDB or Nikto ID |
| `name` | Finding message |
| `severity` | Mapped severity |
| `matched_at` | Target URL |
| `discovery_source` | `nikto` |

## SSL Mode

When `ssl=True`:
- Adds `-ssl` flag
- Connects via HTTPS
- Required for port 443 and other TLS services

## Timeout Handling

- `nikto_timeout` is internal Nikto timeout
- subprocess timeout adds 30s buffer
- Partial results not recoverable on timeout

## Security Notes

- Input validation via `validate_target()` and `validate_port()`
- `-nointeractive` prevents prompts
- Rate limiting via Nikto's internal controls

## Common Findings

| Finding | Severity | Description |
|---------|----------|-------------|
| TRACE method enabled | Medium | HTTP TRACE can expose cookies |
| Directory listing | Low | Exposes file structure |
| Backup files | Medium | May contain sensitive data |
| Missing security headers | Low | Client-side protection missing |
| Server version disclosed | Info | Banner grabbing |

## Related

- [OWASP ZAP](zap.md) - Active web application scanning
- [Scan Lifecycle](../scan-lifecycle.md) - Phase 8 details
