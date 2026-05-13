# Extending Scanners

After reading this you'll understand:
- How to add a new external scanner to PEEK.
- Where to put wrappers, parsers, and how to wire Celery orchestration.
- How to store results (`ToolExecution`/`Vulnerability`) and surface them in the UI.
- How `scan_mode`, exclusions, `NucleiProfile`, and rate limits affect extensions.
- A worked example pattern based on the Nmap → Nuclei pipeline.

## High-Level Steps to Add a New Tool

1. **Wrapper** (`backend/app/tools/`): Create a runner that builds/executes the tool command, enforces timeouts, captures stdout/stderr/output file.
2. **Parser** (`backend/app/parsers/`): Parse raw output into structured data. Return dicts or create model instances.
3. **Models**: Reuse `ToolExecution` for run metadata. If producing findings, consider `Vulnerability` or a new model; link to `ScanTarget` and `Port` when applicable.
4. **Tasks** (`backend/app/tasks/scan_tasks.py` or a new task): Create the `ToolExecution`, run the wrapper, store raw output/error/exit_code, then call the parser to persist structured results.
5. **Service/profile logic** (optional): If the tool is service-aware, add mapping logic (similar to `service_profile.py`) or reuse existing profiles.
6. **UI**: Expose results by adding API endpoints/fields (in routers) and rendering in the Frontend (e.g., new section in `ScanDetail`).

## Directory Placements

| Component | Location | Notes |
|-----------|----------|-------|
| Wrapper | `backend/app/tools/<tool>.py` | Build command args, use timeouts, return `(success, raw_output, error)` |
| Parser | `backend/app/parsers/<tool>_parser.py` | Convert raw output to model instances |
| Task | `backend/app/tasks/scan_tasks.py` or new file | Add phase or dedicated Celery task |
| Config | `backend/config/<tool>_profiles.yaml` | Optional YAML for service-aware mapping |
| Schema | `backend/app/schemas/` | Add toggles/args if user-controllable |
| Model | `backend/app/models/` | Extend or create new models |

## Storing Results

### Always Create a `ToolExecution`

```python
tool_execution = ToolExecution(
    scan_target_id=target.id,
    port_id=port.id,  # Optional, for per-port tools
    tool_name="your_tool",
    command_line=cmd,
    raw_output=output,
    raw_format="json",  # or "text", "xml"
    exit_code=exit_code,
    started_at=start_time,
    completed_at=end_time
)
```

### For Findings

- **`Vulnerability`**: Use for vulnerability-centric findings (template_id, name, severity, host, port, tags, references)
- **New model**: Create if data is different (e.g., compliance checks); link to `ScanTarget` and optionally `Port`

## Wiring into the Pipeline (Celery)

Pattern from Nuclei phase:

1. Filter applicable `Port`s/`ScanTarget`s
2. Build command/target per item (respecting profiles/`scan_mode`)
3. Validate inputs before running (e.g., tag validation for Nuclei)
4. Apply exclusions/rate limits/timeouts per profile
5. Run the tool, store `ToolExecution`, parse output, create findings, update scan stats

### Per-Port vs Per-Target

| Tool Type | `ToolExecution` Links |
|-----------|----------------------|
| Per-port (Nuclei, ssh-audit) | `scan_target_id` + `port_id` |
| Per-target (Nmap) | `scan_target_id` only |

## Scan Modes, Exclusions, Profiles, Rate Limits

| Feature | Description | Example |
|---------|-------------|---------|
| **Scan modes** | `fast` vs `deep` semantics | Apply to target selection/flags |
| **Exclusions** | Config to list patterns/targets/templates to skip | Pass as CLI flags |
| **Profiles** | Service-aware mapping per service/product/port | Like `NucleiProfile` |
| **Rate limits/timeouts** | Per-profile overrides | `rate_limit`, `timeout_multiplier` |
| **Validation** | Pre-flight check (e.g., template availability) | Skip pointless runs |

## Frontend/Display Considerations

1. Extend API responses to expose new findings/sections
2. Add router endpoints if needed
3. Update Frontend API client (`frontend/src/api/`)
4. Add rendering in `ScanDetail` (or new page/section)
5. Keep severity/typing consistent for UI filtering

## Worked Example: Nmap → Nuclei Pattern

| Step | Component | Description |
|------|-----------|-------------|
| Nmap | `tools/nmap.py` | `run_nmap_discovery`, `run_nmap`; writes XML |
| Parser | `parsers/nmap_parser.py` | Populates `Port` with `service_name`, `product`, `version` |
| Profiles | `services/service_profile.py` | Decides `target_format`, tags, `scan_mode` behavior, exclusions, rate limits |
| Validation | `validate_tags()` | Ensures tags have templates; skips `Port`s otherwise |
| Nuclei | `tools/nuclei.py` | Per-port command with flags |
| Parser | `parsers/nuclei_parser.py` | Creates `Vulnerability` linked to `ToolExecution`, `ScanTarget`, `Port` |
| UI | `ScanDetail` | Renders vulnerabilities; ports/services displayed |

## Tips

- Keep wrappers idempotent and return clear errors
- Truncate stored `raw_output` if huge; store `parsed_output` for debugging
- Add logging around decisions (skips due to exclusions/validation)
- Reuse existing patterns: one `ToolExecution` per run, link to ports/targets, parse to structured models
- Update diagrams in `docs/mermaid/` when adding new workflows

## Related Documentation

- **Backend**: [`backend.md`](backend.md) — Celery tasks, parsers
- **NucleiProfile mapping**: [`tools/nuclei.md`](tools/nuclei.md) — Service profiles
- **Data model**: [`data-model.md`](data-model.md) — Entity relationships
- **Contributing**: [`../CONTRIBUTING.md`](../CONTRIBUTING.md) — PR requirements
