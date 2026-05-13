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
katana -u <target> -jsonl -silent -nc -d 2 -c 10 \
       -rate-limit 150 -timeout 120 -field-scope rdn \
       -automatic-form-fill -o output.jsonl
```

## Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `enable_katana` | Enable endpoint discovery | true |
| `katana_max_depth` | Maximum crawl depth | 3 |

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `depth` | Crawl depth limit | 2 |
| `timeout` | Overall timeout (seconds) | 120 |
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

- Returns partial results on timeout
- Continues if some endpoints found before timeout
- Reports timeout error with endpoint count

## Security Notes

- Shell metacharacter validation
- Rate limiting protects target
- Scope restriction prevents off-target crawling
- Form fill is passive (no submission)

## Related

- [httpx](httpx.md) - Provides URLs for Katana to crawl
- [Nuclei](nuclei.md) - Scans discovered endpoints
- [Scan Lifecycle](../scan-lifecycle.md) - Phase 3.5 details
