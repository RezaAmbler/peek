# OWASP ZAP

OWASP ZAP (Zed Attack Proxy) performs web application security testing in Phase 9.

## Phase

| Phase | Purpose |
|-------|---------|
| 9 | Web application security testing (spider + passive scan) |

## Wrapper Location

`backend/app/tools/zap.py`

## Parser Location

`backend/app/parsers/zap_parser.py`

## Architecture

ZAP runs as a separate Docker container:

```yaml
services:
  zap:
    image: zaproxy/zap-stable
    ports:
      - "8090:8080"
```

PEEK connects to ZAP via HTTP API at `http://zap:8080`.

## Function

```python
def run_zap_baseline(
    target_url: str,
    timeout: int = 300,
    spider_timeout: int = 60
) -> Tuple[bool, Optional[str], Optional[str]]
```

## Scan Process

1. **Wait for ZAP**: Check ZAP is ready via `/JSON/core/view/version/`
2. **Start Spider**: `POST /JSON/spider/action/scan/`
3. **Monitor Spider**: Poll `/JSON/spider/view/status/` until complete
4. **Wait for Passive Scan**: Allow 5 seconds for processing
5. **Get Alerts**: `GET /JSON/core/view/alerts/`

## Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `enable_zap` | Enable ZAP scanning | true |
| `zap_scan_type` | Scan type | `baseline` |
| `zap_timeout` | Overall timeout | 300s |

## Spider Settings

| Parameter | Value | Description |
|-----------|-------|-------------|
| `maxChildren` | 10 | Limit child pages per URL |
| Spider timeout | 60s | Spider phase timeout |

## Alert Format

ZAP returns alerts as JSON:

```json
{
    "alerts": [
        {
            "pluginId": "10021",
            "alert": "X-Content-Type-Options Header Missing",
            "risk": "Low",
            "confidence": "Medium",
            "url": "http://example.com/",
            "method": "GET",
            "description": "The Anti-MIME-Sniffing header...",
            "solution": "Set the X-Content-Type-Options header...",
            "reference": "https://owasp.org/...",
            "cweid": "693",
            "wascid": "15"
        }
    ]
}
```

Parsed into:

```python
{
    "alert_id": "10021",
    "name": "X-Content-Type-Options Header Missing",
    "severity": "low",
    "confidence": "Medium",
    "url": "http://example.com/",
    "method": "GET",
    "param": "",
    "attack": "",
    "evidence": "",
    "description": "...",
    "solution": "...",
    "reference": "...",
    "cwe": "693",
    "wasc": "15",
    "tags": {}
}
```

## Severity Mapping

| ZAP Risk | PEEK Severity |
|----------|---------------|
| High | high |
| Medium | medium |
| Low | low |
| Informational | info |

## Database Integration

ZAP findings create `Vulnerability` records:

| Field | Value |
|-------|-------|
| `template_id` | ZAP plugin ID |
| `name` | Alert name |
| `severity` | Mapped severity |
| `matched_at` | Affected URL |
| `discovery_source` | `zap` |
| `description` | Full description |
| `reference` | OWASP references |

## Scan Types

### Baseline Scan (Current)
- Spider + passive scan
- Non-invasive
- Finds misconfigurations and missing headers
- Fast (1-2 minutes)

### Full Scan (Future)
- Active scanning
- Finds injection vulnerabilities
- More invasive
- Slower (10-30 minutes)

## Common Findings

| Finding | Severity | Description |
|---------|----------|-------------|
| Missing X-Frame-Options | Medium | Clickjacking protection |
| Missing CSP | Medium | Content Security Policy |
| Missing X-Content-Type-Options | Low | MIME sniffing protection |
| Cookie without HttpOnly | Low | XSS cookie theft |
| Cookie without Secure | Low | Cookie over HTTP |
| Server version disclosed | Info | Information disclosure |

## Error Handling

| Scenario | Behavior |
|----------|----------|
| ZAP not ready | Returns error after 30s wait |
| Spider fails | Continues with partial results |
| Status check failures | Aborts after 5 consecutive failures |
| API timeout | Returns available alerts |

## Container Configuration

ZAP container requirements:
- Port 8080 exposed (mapped to 8090 externally)
- API accessible without authentication
- Sufficient memory for large sites

## Security Notes

- ZAP API runs without authentication (Docker network isolation)
- Spider respects `maxChildren` limit
- Passive scan only (no active attacks in baseline)
- Timeout handling prevents hanging scans

## Related

- [Nikto](nikto.md) - Web server scanning
- [Scan Lifecycle](../scan-lifecycle.md) - Phase 9 details
