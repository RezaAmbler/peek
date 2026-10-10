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
| Redirects | `-fr -maxr 10 -include-chain` | Follow up to 10 redirects; `-include-chain` puts the chain in the JSON |
| Tech detect | `-td` | Technology fingerprinting |
| TLS data | `-tls-grab` | TLS version/cipher info (the `tls` JSON object) |
| JARM | `-jarm` | JARM TLS fingerprint |
| CDN | `-cdn` | CDN / WAF detection |
| Screenshots | `-ss -system-chrome -ho=--no-sandbox -esb -ehb -srd <dir> -st <n>s` | Webpage screenshots |
| Vhost | `-vhost` | Virtual host detection |
| No update check | `-duc` | The binary is pinned by the image |

### Verified against httpx v1.12.0

Flags and JSON field names were checked against the upstream source at tag `v1.12.0`
(`runner/options.go`, `runner/types.go`, `runner/runner.go`, `runner/headless.go`).
Differences from what PEEK used before:

| Was | Now | Why |
|-----|-----|-----|
| `-ssw <n>` | `-st <n>s` | `-ssw` does not exist in 1.12.0 (unknown flag = exit 2). `-st`/`--screenshot-timeout` takes a duration. |
| `-tls-probe` | `-tls-grab` | `-tls-probe` also sends probes to every hostname in the certificate (hosts outside the scan target). `-tls-grab` returns the same `tls` object without that. |
| _(none)_ | `-include-chain` | The `chain` field is only emitted with this flag. |
| glob `*.png` in `-srd` dir | recursive search | Screenshots are written to `<srd>/screenshot/<host>/<hash>.png`. |
| JSON `jarm` | JSON `jarm_hash` | Field name in 1.12.0 (the old name is still accepted). |
| JSON `cdn` as a name | `cdn_name` + `cdn_type` | `cdn` is a boolean; `cdn_type` is `cdn`, `waf` or `cloud`. A `waf` type is stored in `HttpxResult.waf`. |
| JSON `vhost` as a list | boolean | httpx only reports *that* the server routes by `Host` header, not the names. `virtual_hosts` therefore stays empty for httpx; the detection flag is in `parsed_output` (`vhost_detected`). |
| JSON `chain` as URL list | list of objects | Each item has `request-url`, `status_code`, `location`; PEEK stores the `request-url` values. |

## Output Format

```json
{
    "url": "http://192.168.1.184:8888",
    "status_code": 200,
    "title": "Apache2 Ubuntu Default Page",
    "webserver": "Apache/2.4.41",
    "tech": ["Apache", "Ubuntu"],
    "content_length": 10918,
    "tls": {"tls_version": "tls13", "cipher": "..."},
    "hash": {"body_md5": "...", "header_md5": "..."},
    "jarm_hash": "29d29d15d29d29d00042d42d000000...",
    "cdn": true, "cdn_name": "cloudflare", "cdn_type": "waf",
    "vhost": true,
    "failed": false
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

Screenshots are opt-in (`httpx_screenshots`, default off). When enabled:
1. The runner creates a private temp directory and passes it as `-srd`
2. httpx drives the Chromium installed in the worker image (`-system-chrome`; it never
   downloads a browser at scan time) and writes `<srd>/screenshot/<host>/<hash>.png`
3. The screenshot path is returned in `HttpxOutput.screenshot_path`
4. The phase copies it to screenshot storage and calls `output.cleanup()`; when no
   screenshot was captured the runner removes the directory itself

Chromium runs with `--no-sandbox` because its sandbox cannot start inside the container
(the worker is an unprivileged user without user-namespace support). The container is
the isolation boundary: only enable screenshots for targets you are authorised to scan.

The image can be built without Chromium (`--build-arg INSTALL_CHROMIUM=false`, about
350 MB smaller). Screenshot runs then fail with "the chrome browser is not installed"
on their `ToolExecution` instead of silently producing nothing.

## Failure handling

- Non-zero exit, timeout or missing binary: `HttpxOutput.success=False` with the stderr
  excerpt in `error`; the real exit code and exact command line are stored on the
  `ToolExecution` (124 = timeout, 127 = not installed).
- Clean exit with no output: the port did not answer HTTP (`error="No HTTP response"`,
  exit code 0) and an `HttpxResult` with `connection_failed=True` is stored.

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
