# Katana

Katana is a web crawler used in Phase 3.5 for endpoint discovery.

## Phase

| Phase | Purpose |
|-------|---------|
| 3.5 | Crawl web applications to discover endpoints, forms, and API paths |

## Wrapper Location

`backend/app/tools/katana.py`

## Parser Location

`backend/app/parsers/katana_parser.py`

## Function

```python
def run_katana(
    target_url: str,
    depth: int = 2,
    timeout: int = 120,
    concurrency: int = 10,
    rate_limit: int = 150,
    max_endpoints: int = 500,
    headless: bool = False,
) -> KatanaOutput
```

**Returns**: `KatanaOutput` dataclass with:
- `success: bool`
- `endpoints: List[KatanaEndpoint]`
- `raw_output: Optional[str]`
- `error: Optional[str]`
- `target_url: Optional[str]`

## Command Pattern

```bash
katana -u <target> -jsonl -silent -nc -duc -d 2 -c 10 \
       -rate-limit 150 -timeout 10 -crawl-duration 120s -field-scope rdn \
       -omit-raw -omit-body -o output.jsonl -automatic-form-fill
```

### Verified against katana v1.8.0

Flags and JSON fields were checked against the upstream source at tag `v1.8.0`
(`cmd/katana/main.go`, `pkg/navigation/request.go`, `pkg/navigation/response.go`).

| Was | Now | Why |
|-----|-----|-----|
| `-timeout <overall>` | `-timeout 10 -crawl-duration <overall>s` | `-timeout` is the per-request timeout ("time to wait for request in seconds"). The overall budget is `-crawl-duration`. |
| _(none)_ | `-omit-raw -omit-body` | The JSONL otherwise embeds raw requests/responses and bodies. |
| `response.content_type` | `response.headers["content-type"]` | There is no `content_type` field; header names are lower-cased. |
| `depth`, `source` | not available | `depth` is not serialised (`json:"-"`); `request.source` is the page the link was found on. PEEK stores depth 0. |
| `-headless` | `-headless -system-chrome -no-sandbox` | Uses the image's Chromium (the phase currently always runs with `headless=False`). |

## Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `enable_katana` | Enable endpoint discovery | true |
| `katana_max_depth` | Maximum crawl depth | 3 |

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `depth` | Crawl depth limit | 2 |
| `timeout` | Overall crawl budget in seconds (`-crawl-duration`) | 120 |
| `request_timeout` | Per-request timeout in seconds (`-timeout`) | 10 |
| `concurrency` | Concurrent requests | 10 |
| `rate_limit` | Requests per second | 150 |
| `max_endpoints` | Maximum endpoints to collect | 500 |
| `headless` | Use headless browser for JS | false |

## Features

| Feature | Flag | Description |
|---------|------|-------------|
| Scope | `-field-scope rdn` | Stay on same root domain |
| Form fill | `-automatic-form-fill` | Passive form detection |
| Headless | `-headless` | JavaScript rendering |

## Output Format

JSONL format (one endpoint per line):

```json
{
    "request": {
        "endpoint": "https://example.com/api/users",
        "method": "GET"
    },
    "response": {
        "status_code": 200,
        "content_type": "application/json"
    },
    "depth": 1,
    "source": "crawl"
}
```

Parsed into `KatanaEndpoint`:

```python
@dataclass
class KatanaEndpoint:
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    depth: int = 0
    source: str = "crawl"  # crawl, form, js, etc.
```

## Database Model

Results stored in `DiscoveredEndpoint`:

| Field | Type | Description |
|-------|------|-------------|
| `url` | String | Full endpoint URL |
| `method` | String | HTTP method |
| `status_code` | Integer | Response status |
| `content_type` | String | MIME type |
| `depth` | Integer | Crawl depth |
| `source` | String | Discovery source |

## Integration with Nuclei

Discovered endpoints feed into Phase 5.5 (Nuclei Endpoint Mode):

1. Katana discovers endpoints in Phase 3.5
2. Endpoints stored in `DiscoveredEndpoint` table
3. Phase 5.5 queries endpoints for the scan target
4. URLs written to temp file
5. `run_nuclei_list()` scans all endpoints

## Timeout Handling

- katana stops by itself when `-crawl-duration` is reached and exits 0 (a normal, complete result)
- The subprocess limit is the crawl budget plus 30 s; if that is hit, or katana exits
  non-zero, the run is recorded as failed (`success=False`, exit code 124 for a timeout)
- Endpoints already written are still stored as partial results, and the error message
  carries their count

## Security Notes

- Shell metacharacter validation
- Rate limiting protects target
- Scope restriction prevents off-target crawling
- Form fill is passive (no submission)

## Related

- [httpx](httpx.md) - Provides URLs for Katana to crawl
- [Nuclei](nuclei.md) - Scans discovered endpoints
- [Scan Lifecycle](../scan-lifecycle.md) - Phase 3.5 details
