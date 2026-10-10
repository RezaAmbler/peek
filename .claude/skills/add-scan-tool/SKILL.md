---
name: add-scan-tool
description: Scaffold a new security scan tool into the PEEK pipeline (runner, parser, phase, ToolExecution linkage, optional model). Use when adding a new scanner like nmap/nuclei/httpx to the scan pipeline.
---

# Add a scan tool to PEEK

Wire a new external security tool into the 12-phase scan pipeline so its findings persist and surface in the API/UI. Follow the project contract in CLAUDE.md → "Adding New Scan Tools" exactly.

## Inputs to gather first

Ask the user (or infer from the request):
- **Tool name** and binary (e.g. `whatweb`).
- **What it scans**: which ports/services (web? ssh? all?) and whether it needs Katana-discovered endpoints.
- **Output format**: JSON / XML / text — drives the parser.
- **Where in the pipeline** it should run (which existing phase it sits near) and its `ScanConfig` toggle name (`enable_<tool>`).
- **Result shape**: does it produce `Vulnerability` rows, or a new structured model?

## Steps

1. **Runner** — create `backend/app/tools/<tool>.py`.
   - Mirror an existing runner with similar output format (`backend/app/tools/nuclei.py` for JSON, `nmap.py` for XML, `sslscan.py` for text).
   - Build the command as a **subprocess argv list** (never `shell=True`); validate/allow-list any target-derived args.
   - Return raw output **and** the exact command line. Add a timeout and handle missing-binary / non-zero exit without killing the scan.
   - Honor `ScanConfig` (`scan_mode`, severity, timeouts) instead of hardcoding.

2. **Parser** — create `backend/app/parsers/<tool>_parser.py`.
   - One parser per tool; copy the structure of the closest sibling (`nuclei_parser.py`, `nmap_parser.py`, `testssl_parser.py`).
   - For XML, use a safe parser (`defusedxml`) — tool output is untrusted. Tolerate empty/malformed output.
   - Return structured objects ready for the model layer.

3. **Model (if needed)** — if results don't fit `Vulnerability`, add `backend/app/models/<tool>_result.py` following an existing structured model (`ssh_audit.py`, `ssl_scan_result.py`, `nse_finding.py`). Then create an Alembic migration (see the `create-migration` skill).

4. **ScanConfig toggle** — add `enable_<tool>` (Boolean, sensible default) to the `ScanConfig` model + migration, and expose it in the relevant Pydantic schema and the frontend config UI if applicable.

5. **Phase wiring** — in `backend/app/tasks/scan_tasks.py`:
   - Insert the phase in the right order with a non-overlapping progress range (see the phase table in CLAUDE.md).
   - Gate it behind `if config.enable_<tool>:`.
   - Create a `ToolExecution` row with `command_line` and `raw_output`.
   - Link findings to `ScanTarget`, the `ToolExecution`, and `Port` where applicable.
   - Check whether `scheduled_scan_tasks.py` needs the same change.

6. **Config profile (optional)** — if the tool is profile-driven, add to `config/<tool>_profiles.yaml` and load with `yaml.safe_load`.

7. **Tests & docs** — add a test under `backend/tests/` (parse a sample output fixture), and update CLAUDE.md's phase table + external-tool list and `backend/Dockerfile.celery` if a new binary must be installed.

## Finish

- Run `make test-backend` (or `pytest`) to confirm nothing breaks.
- Suggest invoking the `scan-tool-reviewer` subagent to verify the integration contract, and `security-reviewer` for the command-construction/parsing safety review.
