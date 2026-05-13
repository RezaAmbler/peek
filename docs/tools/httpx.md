# httpx

httpx is an HTTP probing tool used in Phase 3 for web server detection and technology fingerprinting.

## Phase

| Phase | Purpose |
|-------|---------|
| 3 | HTTP probing with tech detection, screenshots, and vhost discovery |

## Wrapper Location

`backend/app/tools/httpx.py`

## Parser Location

`backend/app/parsers/httpx_parser.py`

## Function

```python
def run_httpx(
    target: str,
    timeout: int = 30,
    follow_redirects: bool = True,
    tech_detect: bool = True,
    tls_probe: bool = True,
    jarm: bool = True,
    screenshots: bool = False,
    screenshot_timeout: int = 10,
    vhost_discovery: bool = False,
    retries: int = 2,
) -> HttpxOutput
```

**Returns**: `HttpxOutput` dataclass with:
- `success: bool`
- `raw_json: Optional[str]`
- `error: Optional[str]`
- `screenshot_path: Optional[Path]`

## Command Pattern

```bash
httpx -u <target> -json -silent -nc -timeout 30 -retries 2 \
      -sc -cl -ct -title -server -hash md5 -o output.json \
      -fr -maxr 10 -td -tls-probe -jarm -cdn
```

## Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `enable_httpx` | Enable HTTP probing | true |
| `httpx_timeout` | Request timeout (seconds) | 30 |
| `httpx_tech_detect` | Enable technology detection | true |
| `httpx_screenshots` | Capture webpage screenshots | false |
| `httpx_screenshot_timeout` | Screenshot wait time | 10s |
| `httpx_vhost_discovery` | Enable virtual host discovery | false |

## Features

| Feature | Flag | Description |
|---------|------|-------------|
| Status code | `-sc` | HTTP response status |
| Content length | `-cl` | Response body size |
| Content type | `-ct` | MIME type |
| Title | `-title` | Page title extraction |
| Server | `-server` | Server header |
| Hash | `-hash md5` | Response body hash |
| Redirects | `-fr -maxr 10` | Follow up to 10 redirects |
| Tech detect | `-td` | Technology fingerprinting |
| TLS probe | `-tls-probe` | TLS version/cipher info |
| JARM | `-jarm` | JARM TLS fingerprint |
| CDN | `-cdn` | CDN detection |
| Screenshots | `-ss -srd <dir>` | Webpage screenshots |
| Vhost | `-vhost` | Virtual host discovery |

## Output Format

```json
{
    "url": "http://192.168.1.184:8888",
    "status_code": 200,
    "title": "Apache2 Ubuntu Default Page",
    "webserver": "Apache/2.4.41",
    "tech": ["Apache", "Ubuntu"],
    "content_length": 10918,
    "tls": {"version": "TLSv1.3", "cipher": "..."},
    "jarm": "29d29d15d29d29d00042d42d000000..."
}
```

Parsed into `HttpxResult` model fields:
- `url`, `status_code`, `title`, `webserver`
- `technologies` (array)
- `tls_version`, `tls_cipher`, `jarm_hash`
- `response_time_ms`, `body_hash`
- `cdn`, `waf`
- `final_url`, `redirect_chain`

## Screenshots

When `httpx_screenshots` is enabled:
1. Creates temp directory for screenshots
2. httpx captures PNG screenshots
3. Screenshot path returned in `HttpxOutput`
4. Caller handles screenshot storage/cleanup

## Database Model

Results stored in `HttpxResult`:

| Field | Type | Description |
|-------|------|-------------|
| `url` | String | Final URL after redirects |
| `status_code` | Integer | HTTP status |
| `title` | String | Page title |
| `webserver` | String | Server header |
| `technologies` | JSON | Detected tech stack |
| `screenshot_path` | String | Path to screenshot file |

## Security Notes

- Shell metacharacter validation via `SHELL_METACHARACTERS`
- Retry logic with configurable count
- Timeout handling for unresponsive servers

## Related

- [Katana](katana.md) - Uses httpx URLs for endpoint crawling
- [Scan Lifecycle](../scan-lifecycle.md) - Phase 3 details
