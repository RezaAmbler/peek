# Backend

After reading this you’ll understand:
- How the backend is structured (packages, key modules).
- How Celery tasks orchestrate Nmap → nuclei.
- Where tool wrappers, parsers, and service profiles live.
- How to extend the scan pipeline (new tools or service profiles).

## Layout (backend/app)
- `tasks/`: Celery orchestration (`scan_tasks.py` runs phases; `scheduled_scan_tasks.py` for recurring scans).
- `tools/`: External tool runners (`nmap.py`, `nuclei.py`, `ssh_audit.py`, etc.).
- `parsers/`: Parse tool output into models (`nmap_parser.py`, `nuclei_parser.py`, `ssh_audit_parser.py`, etc.).
- `services/`: Shared logic (e.g., `service_profile.py` for nuclei mapping).
- `models/`: SQLAlchemy models (Scan, ScanTarget, Port, ToolExecution, Vulnerability, ScanConfig, etc.).
- `core/config.py`: Settings, paths to tools (NMAP_PATH, NUCLEI_PATH, etc.).

## Scan orchestration (Celery)
- Entry: `run_scan` in `tasks/scan_tasks.py`:
  - Phase 1: Nmap discovery (creates Ports with state=open).
  - Phase 2: Nmap service detection (enriches Ports with service_name/product/version/extra_info).
  - Phase 3: Optional ssh-audit on SSH ports.
  - Phase 4: Nuclei per-port (service-aware; honors scan_mode, exclusions, tag validation).
- ToolExecution is created per tool run with command_line, timing, raw_output, exit_code, and links to ScanTarget (and Port for per-port runs like nuclei).

## Tool wrappers
- `tools/nmap.py`: Builds Nmap commands for discovery and service detection; writes XML; parsed by `parsers/nmap_parser.py`.
- `tools/nuclei.py`: Builds nuclei commands per target/port:
  - `-target <target>` `-severity <severity_string>` `-jsonl-export <tmp>` `-silent -no-color -no-interactsh -rate-limit <profile or default 150>`
  - Optional `-tags <comma>` when profile tags are non-empty (HTTP fast mode applies targeted HTTP tags).
  - Optional `-templates <path>` from config (overrides tag filtering).
  - Optional `-exclude-templates <pattern>` from `nuclei_profiles.yaml`.
- `tools/ssh_audit.py`: Runs ssh-audit on configured SSH ports.

## Parsers
- `parsers/nmap_parser.py`: Updates Ports with service detection results (service_name, product, version, extra_info).
- `parsers/nuclei_parser.py`: Parses nuclei JSONL; creates Vulnerabilities linked to ScanTarget, ToolExecution, and Port when provided; stores severity as reported (low/info included if nuclei was configured to emit them).
- `parsers/ssh_audit_parser.py`: Stores SSH audit findings per Port.

## Service profiles (nuclei mapping)
- Module: `services/service_profile.py`.
- Config: `config/nuclei_profiles.yaml`.
- Given a Port’s `service_name`/`product`/`version`, returns a NucleiProfile with:
  - `should_scan`, `target_format` (`url` or `host_port`), `protocol`, `tags`, `timeout_multiplier`, optional `rate_limit`.
  - Product tags may be added based on product substring matches (e.g., apache, nginx, haproxy, mysql).
  - Unknown services can fall back to tags `[service_name, network]` when enabled (`scan_unknown_services`).
- Scan modes: `scan_mode` from ScanConfig (`fast`/`deep`) influences HTTP tags (fast mode applies `scan_modes.fast.http_tags` + product tags; deep runs comprehensive).
- Exclusions: `excluded_templates` from YAML passed to nuclei as `-exclude-templates`.
- Tag validation: `validate_tags` checks that tags map to at least one template (`nuclei -tl -tags ...`); ports are skipped with a warning if no templates.
- Used in `run_nuclei_phase` to decide whether/how to run nuclei per port (respecting scan_mode, exclusions, tag validation).

## Extending the backend
- Add a new tool:
  - Create a runner in `tools/` and a parser in `parsers/`.
  - Add a phase or hook in `tasks/scan_tasks.py` (or a dedicated Celery task) and create ToolExecution records.
  - Store parsed results in new or existing models.
- Add a new service → nuclei profile:
  - Edit `config/nuclei_profiles.yaml` to add service profiles and/or product tags.
  - Reload or redeploy; the mapper in `service_profile.py` will pick up the new profile.
- Adjust nuclei severity/tags/templates/mode:
  - Set `nuclei_severity` (include `low,info` to surface those in the UI).
  - Set `nuclei_templates` for a custom template path (overrides tags).
  - Set `scan_mode` (`fast`/`deep`) to influence HTTP tags and breadth.
  - Update `excluded_templates` or `scan_modes` in YAML for exclusions and mode-specific behavior.

## Useful diagrams
- High-level: `mermaid/overview.mmd`
- Scan flow: `mermaid/scan-lifecycle.mmd`
- Data model: `mermaid/data-model.mmd`
- Detailed Nmap→Nuclei pipeline: `mermaid/nmap-nuclei-pipeline.mmd`
