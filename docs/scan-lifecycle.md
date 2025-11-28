# Scan Lifecycle

After reading this you’ll understand:
- How a scan progresses from user action to nuclei results in the UI.
- Where Nmap, service profiles, and nuclei fit.
- How severities (including low/info) are handled.

## End-to-end flow (summary)
1) User creates/starts a scan via the frontend/API. Backend stores `Scan` and `ScanTarget` records.  
2) Worker (Celery) runs discovery (Nmap top ports) → creates `Port` rows (open ports).  
3) Worker runs Nmap service detection on open ports → updates `Port` with `service_name`, `product`, `version`, `extra_info`.  
4) For each open port, worker asks `service_profile.get_nuclei_profile` (config in `backend/config/nuclei_profiles.yaml`) to decide:
   - target format (`url` vs `host:port`), protocol for URLs,
   - tags (empty = comprehensive) and timeout multiplier, optional rate_limit per profile,
   - whether to scan unknown services (configurable fallback),
   - apply scan mode (`scan_mode` from ScanConfig: `fast` or `deep`) for HTTP tags and behaviors.
5) Tag validation: if a profile has tags, the worker validates that nuclei has templates for those tags (`nuclei -tl -tags ...`). Ports are skipped (with a warning) if no templates match.
6) Exclusions: global template exclusions from `nuclei_profiles.yaml` are passed to nuclei as `-exclude-templates ...`.
7) Worker builds nuclei targets with `build_nuclei_target` and runs nuclei **per port** with:
   - `-target <target>`
   - `-severity <config.nuclei_severity>` (defaults to include `critical..info`; adjust by scan mode if desired)
   - `-jsonl-export <file>`
   - `-silent -no-color -no-interactsh`
   - `-rate-limit` (profile-specific or default 150)
   - optional `-tags <comma>` when profile tags are non-empty (HTTP fast mode uses targeted HTTP tags)
   - optional `-templates <path>` when `config.nuclei_templates` is set
   - optional `-exclude-templates <pattern>` from exclusions
8) Nuclei output (JSONL) is parsed; `Vulnerability` records are stored with severity, port linkage, and template info.  
9) Frontend pages fetch and display Ports and Vulnerabilities. LOW/INFO rows appear when the severity filter includes them (e.g., default deep mode).

## Mermaid: scan lifecycle
See `docs/mermaid/scan-lifecycle.mmd`. Inline view:
```mermaid
%% See docs/mermaid/scan-lifecycle.mmd for the source of truth
flowchart TD
  U[User] --> FE[Frontend]
  FE --> API[Backend API]
  API --> W[Worker (Celery)]
  W --> D1[Nmap discovery]
  D1 --> P1[Ports created]
  W --> D2[Nmap service detection]
  D2 --> P2[Ports updated with service/product/version]
  P2 --> SP[service_profile + nuclei_profiles.yaml\n(scan_mode, exclusions, tag validation)]
  SP --> NQ[Build nuclei target + tags]
  NQ --> NR[Run nuclei per port\n(-severity/-tags/-rate/-exclude-templates)]
  NR --> NP[Parse JSONL]
  NP --> DB[(DB: Ports, ToolExecution, Vulnerability)]
  DB --> API --> FE
  FE --> U
```

## Key files (for deeper reading)
- Orchestration: `backend/app/tasks/scan_tasks.py` (`run_scan`, `run_nuclei_phase`)
- Nmap runner/parser: `backend/app/tools/nmap.py`, `backend/app/parsers/nmap_parser.py`
- Service mapping: `backend/app/services/service_profile.py`, `backend/config/nuclei_profiles.yaml`
- Nuclei runner/parser: `backend/app/tools/nuclei.py`, `backend/app/parsers/nuclei_parser.py`
- Models: `Scan`, `ScanTarget`, `Port`, `ToolExecution`, `Vulnerability`

## Severity handling
- Default severity filter: `critical,high,medium`. Set `nuclei_severity` to include `low,info` so those show in the UI tables.
- Nuclei findings are stored with their reported severity; no post-filtering beyond what nuclei emits.

See also: `usage-guide.md` for practical steps and `troubleshooting.md` for common issues.
