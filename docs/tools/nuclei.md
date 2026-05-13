# Nuclei

Nuclei is a template-based vulnerability scanner used in Phases 5 and 5.5.

## Phases

| Phase | Purpose | Function |
|-------|---------|----------|
| 5 | Per-Port Scanning | `run_nuclei()` - Scan each discovered port |
| 5.5 | Endpoint Scanning | `run_nuclei_list()` - Scan discovered endpoints |

## Wrapper Location

`backend/app/tools/nuclei.py`

## Parser Location

`backend/app/parsers/nuclei_parser.py`

## Functions

### run_nuclei()

Scans a single target (URL or host:port).

```python
def run_nuclei(
    target_url: str = None,
    target: str = None,
    severity: str = "critical,high,medium",
    templates: Optional[str] = None,
    tags: Optional[List[str]] = None,
    timeout: int = 300,
    rate_limit: int = 150,
    exclude_templates: Optional[List[str]] = None
) -> Tuple[bool, str, Optional[str]]
```

**Command Pattern**:
```bash
nuclei -target <target> -severity critical,high,medium -jsonl-export output.jsonl \
       -silent -no-color -no-interactsh -omit-raw -rate-limit 150
```

### run_nuclei_list()

Scans a list of URLs from discovered endpoints (Phase 5.5).

```python
def run_nuclei_list(
    urls_file: str,
    severity: str = "critical,high,medium",
    tags: Optional[List[str]] = None,
    timeout: int = 600,
    rate_limit: int = 50,
    exclude_templates: Optional[List[str]] = None
) -> Tuple[bool, str, Optional[str]]
```

**Default Tags for Endpoint Mode**: `http`, `cve`, `exposure`, `misconfig`, `tech`

## Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `nuclei_severity` | Severity filter | `critical,high,medium` |
| `nuclei_templates` | Custom template path | None |
| `nuclei_timeout` | Per-target timeout | 300s |
| `enable_nuclei` | Enable per-port scanning | true |
| `enable_nuclei_endpoints` | Enable endpoint scanning | true |

## NucleiProfile Mapping

PEEK uses `nuclei_profiles.yaml` to map services to appropriate Nuclei tags:

```yaml
service_profiles:
  ssh:
    should_scan: true
    target_format: host_port
    protocol: null
    tags: [ssh, network]
  http:
    should_scan: true
    target_format: url
    protocol: http
    tags: [http, cve, exposure]
```

See `backend/app/services/service_profile.py` for the mapping logic.

## Output Format

Nuclei outputs JSONL (one JSON object per line):

```json
{
    "template-id": "CVE-2023-12345",
    "info": {
        "name": "Vulnerability Name",
        "severity": "high",
        "description": "...",
        "reference": ["https://..."],
        "tags": ["cve", "wordpress"]
    },
    "type": "http",
    "host": "http://example.com",
    "matched-at": "http://example.com/admin",
    "extracted-results": ["..."],
    "curl-command": "curl -X GET ..."
}
```

Parsed into:

```python
{
    "template_id": "CVE-2023-12345",
    "name": "Vulnerability Name",
    "severity": "high",
    "type": "cve",
    "matched_at": "http://example.com/admin",
    "host": "http://example.com",
    "port": 80,
    "extracted_results": ["..."],
    "description": "...",
    "reference": ["https://..."],
    "tags": ["cve", "wordpress"]
}
```

## Port Extraction

The `extract_port_from_matched_at()` function handles various URL formats:

- `203.0.113.10:22` → port 22 (network services)
- `http://example.com:8080/path` → port 8080
- `https://example.com/path` → port 443 (default)
- `ssh://host:22` → port 22

## Scan Modes

| Mode | Behavior |
|------|----------|
| `fast` | Uses targeted HTTP tags for web services |
| `deep` | Comprehensive scanning with all relevant templates |

## Security Notes

- Shell metacharacter validation prevents command injection
- Rate limiting protects target systems
- `--no-interactsh` disables out-of-band testing for faster scans

## Related

- [Katana](katana.md) - Provides endpoints for Phase 5.5
- [NucleiProfile Mapping](../backend.md#nucleiprofile-mapping)
- [Scan Lifecycle](../scan-lifecycle.md) - Phases 5 and 5.5
