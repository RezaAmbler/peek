# Extending Scanners

After reading this you’ll understand:
- How to add a new external scanner to PEEK.
- Where to put wrappers, parsers, and how to wire Celery orchestration.
- How to store results (ToolExecution/Vulnerability) and surface them in the UI.
- How scan modes, exclusions, profiles, and rate limits affect extensions.
- A worked example pattern based on the Nmap → Nuclei pipeline.

## High-level steps to add a new tool
1) **Wrapper** (`backend/app/tools/`): Create a runner that builds/executes the tool command, enforces timeouts, captures stdout/stderr/output file.
2) **Parser** (`backend/app/parsers/`): Parse raw output into structured data. Return dicts or create model instances.
3) **Models**: Reuse `ToolExecution` for run metadata. If producing findings, consider `Vulnerability` or a new model; link to `ScanTarget` and `Port` when applicable.
4) **Tasks** (`backend/app/tasks/scan_tasks.py` or a new task): Create the ToolExecution, run the wrapper, store raw output/error/exit_code, then call the parser to persist structured results.
5) **Service/profile logic** (optional): If the tool is service-aware, add mapping logic (similar to `service_profile.py`) or reuse existing profiles.
6) **UI**: Expose results by adding API endpoints/fields (in routers) and rendering in the frontend (e.g., new section in `ScanDetail`).

## Directory placements
- **Wrapper**: `backend/app/tools/<tool>.py`
  - Follow nuclei/nmap patterns: build command args, use timeouts, return `(success, raw_output, error)`.
- **Parser**: `backend/app/parsers/<tool>_parser.py`
  - Convert raw output to model instances; store parsed_output on ToolExecution if helpful.
- **Task integration**:
  - If it’s part of the main scan pipeline, add a phase in `scan_tasks.py` similar to ssh-audit/nuclei.
  - Else, create a dedicated Celery task and call it from the API/worker.
- **Config**:
  - Add toggles/args/rate limits to `ScanConfig`/schemas if user-controllable (e.g., enable_<tool>, timeout, severity).
  - If tool is service-aware, add profiles in a YAML akin to `nuclei_profiles.yaml`.

## Storing results
- Always create a `ToolExecution`:
  - `tool_name`, `command_line` (if known), `raw_output`, `raw_format`, `exit_code`, timestamps, `scan_target_id`, and optionally `port_id`.
- For findings, use:
  - `Vulnerability` (template_id/name/severity/host/port/tags/etc.) if it’s vulnerability-centric.
  - A new model if the data is different (e.g., compliance checks), linked to `ScanTarget` and optionally `Port`.

## Wiring into the pipeline (Celery)
- Pattern from Nuclei phase:
  - Filter applicable Ports/Targets.
  - Build command/target per item (respecting profiles/scan_mode).
  - Validate inputs (e.g., tag validation for nuclei) before running to avoid “no-template” runs.
  - Apply exclusions/rate limits/timeouts per profile.
  - Run the tool, store ToolExecution, parse output, create findings, update scan stats.
- For per-port tools: link ToolExecution and findings to `Port`.
- For per-target tools: link to `ScanTarget`.

## Scan modes, exclusions, profiles, rate limits
- **Scan modes**: If your tool has “fast vs deep” semantics, take a `scan_mode` from ScanConfig (like nuclei) and apply it to target selection/flags.
- **Exclusions**: Provide a config (YAML) to list patterns/targets/templates to skip; pass exclusions as CLI flags if supported.
- **Profiles**: Use a `service_profile`-like mapper to choose tags/flags/targets per service/product/port; allow port_hints for unknown services.
- **Rate limits/timeouts**: Allow per-profile overrides (see nuclei profiles’ `rate_limit` and `timeout_multiplier`), fallback to config defaults.
- **Validation**: If the tool can pre-flight check (e.g., template availability), do it (like nuclei tag validation) to skip pointless runs.

## Frontend/display considerations
- Extend API responses to expose new findings/sections; add router endpoints if needed.
- Update frontend API client (`frontend/src/api/`) and `ScanDetail` (or new page/section) to render the new data.
- Keep severity/typing consistent where applicable so the UI can group/sort/filter.

## Worked example (Nmap → Nuclei pattern)
- **Nmap**: `tools/nmap.py` run_nmap_discovery/run_nmap; `parsers/nmap_parser.py` populates Ports with service/product/version.
- **Profiles**: `services/service_profile.py` + `config/nuclei_profiles.yaml` decide target_format, tags, scan_mode behavior, exclusions, rate limits.
- **Validation**: `validate_tags` ensures tags have templates; skips ports otherwise.
- **Nuclei**: `tools/nuclei.py` builds per-port command with `-target -severity -jsonl-export -silent -no-color -no-interactsh -rate-limit <profile/default> [-tags] [-templates] [-exclude-templates]`.
- **Parse/store**: `parsers/nuclei_parser.py` → `Vulnerability` linked to `ToolExecution`, `ScanTarget`, and `Port`.
- **UI**: `ScanDetail` renders vulnerabilities across severities; ports/services are displayed; config options are managed in `Configs` (extend to expose new tool toggles if needed).

## Tips
- Keep wrappers idempotent and return clear errors.
- Truncate stored raw_output if huge; store parsed_output for debugging.
- Add logging around decisions (skips due to exclusions/validation).
- Reuse existing patterns: one ToolExecution per run, link to ports/targets, parse to structured models, surface via API and UI.
