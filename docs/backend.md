# Backend

After reading this you'll understand:
- How the backend is structured (packages, key modules).
- The config-centric architecture where configs define targets.
- How Celery tasks orchestrate the 12-phase scan pipeline.
- Where tool wrappers, parsers, and `NucleiProfile` mapping live.
- How comparisons work with same-config validation.

## Config-Centric Architecture

The backend implements a config-centric model:

1. **ScanConfig contains targets**: `targets` is a JSON array of IPs/hostnames
2. **Scan is an execution**: Each scan gets an auto-incremented `run_number` per config
3. **Targets copied at start**: Worker copies `config.targets` to `ScanTarget` rows
4. **Same-config comparisons**: Comparison API validates `config_id` matches

## Layout (`backend/app/`)

| Directory | Purpose |
|-----------|---------|
| `tasks/` | Celery orchestration (`scan_tasks.py` runs 12 phases; `scheduled_scan_tasks.py` for recurring scans) |
| `tools/` | External tool runners (11 tools: nmap, nuclei, ssh_audit, httpx, katana, sslscan, testssl, nikto, zap, nmap_nse, masscan) |
| `parsers/` | Parse tool output into models (11 parsers) |
| `services/` | Shared logic (`service_profile.py` for `NucleiProfile` mapping, `comparison_service.py` for diff generation, `port_classifier.py`, `url_normalizer.py`) |
| `models/` | SQLAlchemy models (`ScanConfig`, `Scan`, `ScanTarget`, `Port`, `ToolExecution`, `Vulnerability`, `HttpxResult`, `DiscoveredEndpoint`, `NseFinding`, `SslScanResult`, `TestsslResult`, `SSHAudit`) |
| `routers/` | API endpoints (scans, configs, comparisons, auth, reports, stats) |
| `schemas/` | Pydantic schemas for API payloads |
| `core/` | Settings (`config.py`), security helpers (`validators.py`, `rate_limit.py`), DB session |

## Scan Orchestration (Celery)

Entry point: `run_scan` in `backend/app/tasks/scan_tasks.py`:

| Phase | Name | Config Toggle | Action | Output |
|-------|------|---------------|--------|--------|
| 1 | Port Discovery | Always on | Nmap discovers open ports | Creates `Port` rows |
| 2 | Service Detection | Always on | Nmap identifies services | Updates `Port` with service info |
| 3 | httpx | `enable_httpx` | HTTP probing with tech detection | Creates `HttpxResult` |
| 3.5 | Katana | `enable_katana` | Crawls web apps for endpoints | Creates `DiscoveredEndpoint` |
| 4 | SSH-Audit | `enable_ssh_audit` | SSH security analysis | Creates `SSHAudit` |
| 5 | Nuclei | `enable_nuclei` | Vulnerability scanning per port | Creates `Vulnerability` |
| 5.5 | Nuclei Endpoints | `enable_nuclei_endpoints` | Scans discovered endpoints | Creates `Vulnerability` |
| 6 | NSE Scripts | `enable_nse` | Nmap scripting engine | Creates `NseFinding` |
| 7 | SSLScan | `enable_sslscan` | Quick TLS analysis | Creates `SslScanResult` |
| 7.5 | testssl.sh | `enable_testssl` | Deep TLS analysis | Creates `TestsslResult` |
| 8 | Nikto | `enable_nikto` | Web server scanning | Creates `Vulnerability` |
| 9 | ZAP | `enable_zap` | OWASP ZAP baseline scan | Creates `Vulnerability` |

`ToolExecution` is created per tool run with `command_line`, timing, `raw_output`, `exit_code`, and links to `ScanTarget` (and `Port` via `port_id` for per-port runs).

## Run Number Assignment

When creating a scan via `POST /api/scans`:

1. Query `MAX(run_number)` for the given `config_id`
2. Assign `run_number = max + 1` (or 1 if first run)
3. Auto-generate name as "Run #N -- YYYY-MM-DD" if not provided

## Comparison Engine

Located in `backend/app/services/comparison_service.py`:

**Validation**:
- Scans must share the same `config_hash` (SHA-256 of canonical-JSON of the comparable fields of `config_snapshot`). `config_id` equality is necessary but not sufficient — editing a config produces a new hash, so post-edit runs are not comparable to pre-edit runs even though they share the same `config_id`.
- Returns an error if hashes differ.
- Auto-swaps `baseline`/`current` if the caller passes them out of chronological order; the diff is always older → newer.

**Snapshot**:
- At scan creation, the worker captures a JSON snapshot of the entire `ScanConfig` (`config_snapshot`) and stores a SHA-256 hash of the canonicalized comparable fields (`config_hash`). See `services/config_snapshot.py`.

**Enriched Output**:
- Port changes include `version`, `product`, `associated_vulnerabilities`
- Vulnerability changes include `matched_at`, severity, template info
- JSON references are preserved for frontend parsing

**Endpoint**: `POST /api/comparisons/compare`
**Helper**: `GET /api/scans/{id}/comparable` returns scans whose `config_hash` matches the given scan, used to populate the compare-modal dropdown.

## Tool Wrappers

| File | Tool | Description |
|------|------|-------------|
| `tools/nmap.py` | Nmap | Port discovery and service detection; writes XML output |
| `tools/nuclei.py` | Nuclei | Vulnerability scanning per port and endpoint-mode; writes JSONL |
| `tools/ssh_audit.py` | ssh-audit | SSH security analysis; returns JSON |
| `tools/httpx.py` | httpx | HTTP probing with tech detection, screenshots, vhost discovery |
| `tools/katana.py` | Katana | Web application crawling for endpoint discovery |
| `tools/nmap_nse.py` | Nmap NSE | Nmap Scripting Engine for service-specific checks |
| `tools/sslscan.py` | sslscan | Quick SSL/TLS cipher and certificate analysis |
| `tools/testssl.py` | testssl.sh | Comprehensive TLS vulnerability analysis |
| `tools/nikto.py` | Nikto | Web server vulnerability scanning |
| `tools/zap.py` | OWASP ZAP | Web application security testing |
| `tools/masscan.py` | masscan | Fast port discovery (legacy, replaced by Nmap discovery) |

## Parsers

| File | Input | Output |
|------|-------|--------|
| `parsers/nmap_discovery_parser.py` | Nmap XML | Creates `Port` rows from discovery |
| `parsers/nmap_parser.py` | Nmap XML | Updates `Port` with service details |
| `parsers/nuclei_parser.py` | Nuclei JSONL | Creates `Vulnerability` linked to `Port` |
| `parsers/ssh_audit_parser.py` | ssh-audit JSON | Creates `SSHAudit` records |
| `parsers/httpx_parser.py` | httpx JSON | Creates `HttpxResult` records |
| `parsers/katana_parser.py` | Katana JSON | Creates `DiscoveredEndpoint` records |
| `parsers/testssl_parser.py` | testssl.sh JSON | Creates `TestsslResult` records |
| `parsers/nikto_parser.py` | Nikto output | Creates `Vulnerability` records |
| `parsers/zap_parser.py` | ZAP JSON | Creates `Vulnerability` records |
| `parsers/masscan_parser.py` | masscan JSON | Creates `Port` rows (legacy) |

## NucleiProfile Mapping

**Module**: `backend/app/services/service_profile.py`
**Config**: `backend/config/nuclei_profiles.yaml`

Given a `Port`'s `service_name`/`product`/`version`, `get_nuclei_profile()` returns a `NucleiProfile` with:

| Field | Description |
|-------|-------------|
| `should_scan` | Whether to scan this service |
| `target_format` | `url` or `host_port` |
| `protocol` | `http`, `https`, or `None` |
| `tags` | Nuclei template tags (empty = comprehensive) |
| `timeout_multiplier` | Scales `nuclei_timeout` |
| `rate_limit` | Optional per-profile rate limit |

## Scheduled Scans

Celery Beat checks `ScanConfig` records with `schedule_enabled=True` and triggers scans based on cron expressions.

When triggered:
1. Creates a new `Scan` with next `run_number`
2. Copies `config.targets` to `ScanTarget` rows
3. Executes normal scan pipeline
4. Updates `last_scheduled_run` on the config

## Security

### Input Validation

All tool wrappers validate inputs before executing subprocess commands:

| Module | Function | Purpose |
|--------|----------|---------|
| `core/validators.py` | `validate_ip_address()` | Validates IPv4/IPv6, blocks shell metacharacters |
| `core/validators.py` | `validate_hostname()` | RFC 1123 validation, blocks shell metacharacters |
| `core/validators.py` | `validate_target()` | Auto-detects IP vs hostname |
| `core/validators.py` | `validate_port()` | Ensures port 1-65535 |

### Authentication Security

| Feature | Location | Description |
|---------|----------|-------------|
| Rate limiting | `core/rate_limit.py` | 5 login attempts per minute per IP |
| Timing attack prevention | `routers/auth.py` | Always verifies password hash (dummy if user not found) |
| Password policy | `schemas/user.py` | Requires uppercase, lowercase, digit; blocks common passwords |
| SECRET_KEY validation | `core/config.py` | Startup fails if SECRET_KEY missing or weak |

## Extending the Backend

### Adding a New Tool
1. Create a runner in `backend/app/tools/<tool>.py`
2. Create a parser in `backend/app/parsers/<tool>_parser.py`
3. Add a phase in `backend/app/tasks/scan_tasks.py`
4. Create `ToolExecution` records with `port_id` linkage
5. Add config toggle in `models/scan_config.py`

### Adding a New NucleiProfile
1. Edit `backend/config/nuclei_profiles.yaml`
2. Add entry to `service_profiles` or `product_tags`
3. Restart Worker; `service_profile.py` will pick up changes

### Adjusting Nuclei Behavior
- **Severity**: Set `nuclei_severity` in `ScanConfig` (include `low,info` for broader findings)
- **Templates**: Set `nuclei_templates` for custom template path
- **Scan mode**: Set `scan_mode` to `fast` or `deep`
- **Exclusions**: Update `excluded_templates` in YAML

## Related Documentation

- **Scan lifecycle**: [`scan-lifecycle.md`](scan-lifecycle.md) -- All 12 phases explained
- **Tool documentation**: [`tools/`](tools/) -- Individual tool deep dives
- **Frontend integration**: [`frontend.md`](frontend.md)
- **Extending scanners**: [`extending-scanners.md`](extending-scanners.md)
- **Diagrams**: [`mermaid/overview.mmd`](mermaid/overview.mmd), [`mermaid/scan-lifecycle.mmd`](mermaid/scan-lifecycle.mmd)
