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
nuclei -severity critical,high,medium -jsonl-export output.jsonl \
       -silent -no-color -no-interactsh -omit-raw -rate-limit 150 \
       -disable-update-check [-tags a,b] [-exclude-templates x] -target <target>
```

### Verified against nuclei v3.11.1

Checked against the upstream source at tag `v3.11.1` (`cmd/nuclei/main.go`,
`pkg/output/output.go`, `pkg/model/model.go`, `pkg/reporting/exporters/jsonl/jsonl.go`,
`internal/runner/runner.go`, `pkg/installer/template.go`):

- Every flag PEEK passes exists with the same meaning: `-target`, `-list`, `-severity`,
  `-jsonl-export`, `-silent`, `-no-color`, `-no-interactsh`, `-omit-raw`, `-rate-limit`,
  `-tags`, `-templates`, `-exclude-templates`, `-tl`, `-disable-update-check`.
- JSON fields read by the parser are unchanged: `template-id`, `info.name`,
  `info.severity`, `info.description`, `info.reference`, `info.tags`, `type`, `host`,
  `matched-at`, `extracted-results`, `curl-command`.
- The JSONL export file is written when nuclei shuts down cleanly (also when there are
  no results), and any fatal error exits with code 1. PEEK therefore decides success
  from the **exit code**: non-zero, timeout or missing binary is a failed
  `ToolExecution` with the stderr excerpt; only exit 0 with an empty export means
  "no vulnerabilities".

### Templates are pinned

The worker image installs `nuclei-templates` at a fixed tag and commit
(`NUCLEI_TEMPLATES_TAG` / `NUCLEI_TEMPLATES_COMMIT` in `backend/Dockerfile.celery`)
instead of running `nuclei -update-templates` at build time, and every nuclei call
passes `-disable-update-check`. Without that flag nuclei 3.x checks for, and installs,
newer templates on each run, so two scans from the same image could use different
template sets. To update templates, bump the tag and commit and rebuild the image.

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

### Custom templates (`nuclei_templates`)

The value is a comma-separated list of paths **relative to the installed
`nuclei-templates` directory** (for example `http/cves/2024,ssl`). Absolute paths,
`..`, URLs and anything that resolves (after following symlinks) outside that
directory are rejected by the API and by the runner, because a template can execute
code and send arbitrary requests. Set `NUCLEI_TEMPLATES_DIR` if the templates are not
in `$HOME/nuclei-templates`.
