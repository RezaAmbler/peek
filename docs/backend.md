# Backend

After reading this you'll understand:
- How the backend is structured (packages, key modules).
- How Celery tasks orchestrate Nmap → Nuclei.
- Where tool wrappers, parsers, and `NucleiProfile` mapping live.
- How to extend the scan pipeline (new tools or service profiles).

## Layout (`backend/app/`)

| Directory | Purpose |
|-----------|---------|
| `tasks/` | Celery orchestration (`scan_tasks.py` runs phases; `scheduled_scan_tasks.py` for recurring scans) |
| `tools/` | External tool runners (`nmap.py`, `nuclei.py`, `ssh_audit.py`) |
| `parsers/` | Parse tool output into models (`nmap_parser.py`, `nuclei_parser.py`, `ssh_audit_parser.py`) |
| `services/` | Shared logic (`service_profile.py` for `NucleiProfile` mapping) |
| `models/` | SQLAlchemy models (`Scan`, `ScanTarget`, `Port`, `ToolExecution`, `Vulnerability`, `ScanConfig`) |
| `routers/` | API endpoints (scans, configs, auth, reports) |
| `schemas/` | Pydantic schemas for API payloads |
| `core/` | Settings (`config.py`), security helpers, DB session |

## Scan Orchestration (Celery)

Entry point: `run_scan` in `backend/app/tasks/scan_tasks.py`:

| Phase | Action | Output |
|-------|--------|--------|
| 1 | Nmap discovery | Creates `Port` rows (`state=open`) |
| 2 | Nmap service detection | Updates `Port` with `service_name`, `product`, `version`, `extra_info` |
| 3 | ssh-audit (optional) | SSH security analysis on configured ports |
| 4 | Nuclei per-port | Runs Nuclei per `Port` (service-aware; honors `scan_mode`, exclusions, tag validation) |

`ToolExecution` is created per tool run with `command_line`, timing, `raw_output`, `exit_code`, and links to `ScanTarget` (and `Port` via `port_id` for per-port runs like Nuclei).

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

**Features**:
- **Product tags**: Added based on product substring matches (e.g., apache, nginx, mysql)
- **Scan modes**: `scan_mode` from `ScanConfig` (`fast`/`deep`) influences HTTP tags
  - `fast`: Uses `scan_modes.fast.http_tags` + product tags
  - `deep`: Uses empty tags (comprehensive)
- **Exclusions**: `excluded_templates` from YAML passed to Nuclei as `-exclude-templates`
- **Tag validation**: `validate_tags()` checks that tags resolve to templates; `Port`s are skipped if no templates match
- **Unknown services**: Fall back to `[service_name, network]` when `scan_unknown_services` is enabled

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
