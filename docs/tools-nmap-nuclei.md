# Nmap & Nuclei Deep Dive

After reading this you’ll understand:
- How Nmap discovery and service detection are invoked and parsed.
- How service_profile + nuclei_profiles.yaml map services/products to nuclei targets/tags.
- How nuclei commands are built per port and how findings flow into the DB (including low/info when configured).

## Nmap
- Discovery (`tools/nmap.py` run_nmap_discovery):
  - Scans top ports (`--top-ports`) with `-Pn -sS -T* --open`, writes XML.
  - Parsed by `parsers/nmap_discovery_parser.py` → creates `Port` rows (state=open).
- Service detection (`tools/nmap.py` run_nmap):
  - Runs with configured args (defaults `-sS -sV -sC -T2 -Pn`) against open ports, writes XML.
  - Parsed by `parsers/nmap_parser.py` → updates `Port` with `service_name`, `product`, `version`, `extra_info` (includes NSE script snippets). SSL/tunnel shows in `service_name` (e.g., `ssl/http`).

## Service → NucleiProfile mapping
- Module: `services/service_profile.py`.
- Config: `config/nuclei_profiles.yaml`.
- Profile fields: `should_scan`, `target_format` (`url` or `host_port`), `protocol`, `tags`, `timeout_multiplier`, optional `rate_limit`.
- Product tags added when product substrings match (e.g., apache/nginx/haproxy/mysql/openssh).
- Unknown services can fall back to `[service_name, network]` when `scan_unknown_services` is true.
- Target builder: `build_nuclei_target` uses profile to produce URL (default port omitted for 80/443) or `ip:port`.
- Scan modes:
  - `scan_mode` (ScanConfig) is passed to `get_nuclei_profile`.
  - YAML `scan_modes.fast.http_tags` applies targeted HTTP tags in fast mode; deep mode uses comprehensive (empty tags) for HTTP.
- Exclusions: `excluded_templates` in YAML are passed to nuclei as `-exclude-templates ...` for every run.
- Tag validation: `validate_tags` checks that tags resolve to at least one template (`nuclei -tl -tags ...`); if none found, the port is skipped with a warning.

## Nuclei invocation
- One nuclei process per scannable Port.
- Command pattern (`tools/nuclei.py`):
  - `nuclei -target <target> -severity <severity_string> -jsonl-export <tmp> -silent -no-color -no-interactsh -rate-limit <profile or default 150>`
  - Optional `-tags <comma>` when profile tags are non-empty.
  - Optional `-templates <path>` (global override from config).
  - Optional `-exclude-templates <pattern>` from YAML exclusions.
  - Timeout: base `config.nuclei_timeout` (or `global_tool_timeout_seconds`) × `timeout_multiplier` from profile.
- Profiles with empty tags (HTTP deep mode) omit `-tags` → broad/comprehensive HTTP coverage.
- HTTP fast mode uses targeted HTTP tags from `scan_modes.fast.http_tags` plus product tags.
- Network services use tags like `[ssh,network]`, `[mysql,network]`, `[redis,network]`, etc., validated before running.

## Parsing and storage
- Nuclei JSONL parsed by `parsers/nuclei_parser.py` → creates `Vulnerability` records.
- Each run has a `ToolExecution` linked to `ScanTarget` and the specific `Port`; vulnerabilities link back to both.
- Severity is stored as reported by nuclei; default `nuclei_severity` includes `critical,high,medium,low,info` (ScanConfig). In fast mode you may still include `low,info` if desired—set the config accordingly to show these in the UI tables.

## Debugging tips
- Check `tool_executions` for raw_output/error_message/command_line and port linkage.
- Verify `ports` have service_name/product/version from Nmap; profiles depend on these.
- Ensure `nuclei_severity` includes desired severities (e.g., `critical,high,medium,low,info`) for broader findings.
- If tags are skipped, look for tag validation warnings; update tags or templates accordingly.
- Adjust `excluded_templates` in YAML if needed to reduce noise or re-include patterns.
