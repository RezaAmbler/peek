# Backend

After reading this you'll understand:
- How the backend is structured (packages, key modules).
- The config-centric architecture where configs define targets.
- How Celery tasks orchestrate Nmap -> Nuclei.
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
| `tasks/` | Celery orchestration (`scan_tasks.py` runs phases; `scheduled_scan_tasks.py` for recurring scans) |
| `tools/` | External tool runners (`nmap.py`, `nuclei.py`, `ssh_audit.py`) |
| `parsers/` | Parse tool output into models (`nmap_parser.py`, `nuclei_parser.py`, `ssh_audit_parser.py`) |
| `services/` | Shared logic (`service_profile.py` for `NucleiProfile` mapping, `comparison_service.py` for diff generation) |
| `models/` | SQLAlchemy models (`ScanConfig`, `Scan`, `ScanTarget`, `Port`, `ToolExecution`, `Vulnerability`) |
| `routers/` | API endpoints (scans, configs, comparisons, auth, reports) |
| `schemas/` | Pydantic schemas for API payloads |
| `core/` | Settings (`config.py`), security helpers, DB session |

## Scan Orchestration (Celery)

Entry point: `run_scan` in `backend/app/tasks/scan_tasks.py`:

| Phase | Action | Output |
|-------|--------|--------|
| 0 | Copy targets from config | Creates `ScanTarget` rows from `config.targets` |
| 1 | Nmap discovery | Creates `Port` rows (`state=open`) |
| 2 | Nmap service detection | Updates `Port` with `service_name`, `product`, `version`, `extra_info` |
| 3 | ssh-audit (optional) | SSH security analysis on configured ports |
| 4 | Nuclei per-port | Runs Nuclei per `Port` (service-aware; honors `scan_mode`, exclusions, tag validation) |

`ToolExecution` is created per tool run with `command_line`, timing, `raw_output`, `exit_code`, and links to `ScanTarget` (and `Port` via `port_id` for per-port runs like Nuclei).

## Run Number Assignment

When creating a scan via `POST /api/scans`:

1. Query `MAX(run_number)` for the given `config_id`
2. Assign `run_number = max + 1` (or 1 if first run)
3. Auto-generate name as "Run #N -- YYYY-MM-DD" if not provided

## Comparison Engine

Located in `backend/app/services/comparison_service.py`:

**Validation**:
- Scans must share the same `config_id`
- Returns error if configs differ

**Enriched Output**:
- Port changes include `version`, `product`, `associated_vulnerabilities`
- Vulnerability changes include `matched_at`, severity, template info
- JSON references are preserved for frontend parsing

**Endpoint**: `POST /api/comparisons/compare`

## Tool Wrappers

| File | Tool | Description |
|------|------|-------------|
| `tools/nmap.py` | Nmap | Builds commands for discovery and service detection; writes XML |
| `tools/nuclei.py` | Nuclei | Builds per-port commands with `-target`, `-severity`, `-jsonl-export`, `-rate-limit`, optional `-tags`/`-templates`/`-exclude-templates` |
| `tools/ssh_audit.py` | ssh-audit | Runs SSH security analysis on configured ports |

## Parsers

| File | Input | Output |
|------|-------|--------|
| `parsers/nmap_parser.py` | Nmap XML | Updates `Port` with `service_name`, `product`, `version`, `extra_info` |
| `parsers/nuclei_parser.py` | Nuclei JSONL | Creates `Vulnerability` linked to `ScanTarget`, `ToolExecution`, and `Port` |
| `parsers/ssh_audit_parser.py` | ssh-audit JSON | Creates SSH audit findings per `Port` |

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

Celery Beat checks `ScheduledScan` records and triggers scans based on cron expressions.

When triggered:
1. Creates a new `Scan` with next `run_number`
2. Copies `config.targets` to `ScanTarget` rows
3. Executes normal scan pipeline
4. Updates `last_scheduled_run` on the config

## Extending the Backend

### Adding a New Tool
1. Create a runner in `backend/app/tools/<tool>.py`
2. Create a parser in `backend/app/parsers/<tool>_parser.py`
3. Add a phase in `backend/app/tasks/scan_tasks.py`
4. Create `ToolExecution` records with `port_id` linkage

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

- **Diagrams**: [`mermaid/overview.mmd`](mermaid/overview.mmd), [`mermaid/scan-lifecycle.mmd`](mermaid/scan-lifecycle.mmd), [`mermaid/nmap-nuclei-pipeline.mmd`](mermaid/nmap-nuclei-pipeline.mmd)
- **Nmap/Nuclei details**: [`tools-nmap-nuclei.md`](tools-nmap-nuclei.md)
- **Frontend integration**: [`frontend.md`](frontend.md)
- **Extending scanners**: [`extending-scanners.md`](extending-scanners.md)
