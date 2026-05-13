# Usage Guide

Practical steps to run scans and read results.

## Run a Fast Scan

1. In the UI: **New Scan** → enter targets → select a `ScanConfig` with `scan_mode=fast` and Nuclei enabled
2. **Fast mode behavior**:
   - HTTP services use targeted tags from `scan_modes.fast.http_tags` + product tags
   - Non-HTTP services use service tags (e.g., `[ssh, network]`), validated before running
   - Exclusions and tag validation apply; `Port`s with no matching templates are skipped
   - Severity comes from `nuclei_severity` in `ScanConfig`
3. Start the scan; progress shows `nuclei` phase when reached

## Run a Deep Scan (Including LOW/INFO)

1. In the UI: **New Scan** → select a `ScanConfig` with:
   - `scan_mode=deep`
   - Nuclei enabled
   - `nuclei_severity` including `low,info` (default Backend value)
2. **Deep mode behavior**:
   - HTTP services use empty tags (comprehensive coverage)
   - Non-HTTP services use service tags
   - Exclusions still apply; tag validation still enforced
   - LOW/INFO severities from Nuclei appear in the vulnerabilities section

## View and Interpret Results

1. From the **Scan list**, open a scan to the **Scan Detail** page
2. **Ports table**: Shows discovered services (`service_name`, `product`, `version`, `state`, source)
3. **Vulnerabilities section**: Lists all severities (CRITICAL/HIGH/MEDIUM/LOW/INFO) returned by Backend
4. **Phase timeline**: Indicates scan progress through 12 phases (see [scan-lifecycle.md](scan-lifecycle.md))

## Compare Two Scans

PEEK compares runs of the **same configuration** to surface infrastructure changes over time.

1. From the **Scan Detail** page of any completed scan, click **Compare**
2. The compare modal's dropdown is populated from `GET /api/scans/{id}/comparable`, which returns only scans whose `config_hash` matches this scan's hash — meaning the configuration was identical at both execution times
3. Pick a comparison partner; the modal displays each option as `Run #N — <date>` so chronology is unambiguous
4. Submit. The API auto-swaps baseline and current to enforce older → newer ordering, then returns enriched diffs:
   - **Port changes**: new, closed, or service-changed ports — each with version/product before/after
   - **Vulnerability changes**: new and resolved findings, grouped by severity, with template IDs and `matched_at` URLs

### Why some scans are not selectable

If you don't see a scan you expected in the dropdown:

| Cause | What to do |
|---|---|
| The config was edited between the two scans | Editing a config produces a new `config_hash`. Runs from before the edit are no longer comparable to runs after. To re-establish a comparable baseline, run a fresh scan on the current config. |
| The two scans are on different configs | Run them on a single shared config; targets live on the config, not the scan. |
| The other scan is still running or failed | Only `completed` scans appear in the comparable list. |

The scan-detail page also shows a short `config_hash` badge near the header, so you can eyeball whether two scans are comparable before opening the modal.

## Understand What Is (Not) Scanned by Nuclei

| Factor | Description |
|--------|-------------|
| `NucleiProfile` | Decides which services get scanned and which tags/rate limits apply |
| Exclusions | `excluded_templates` are always passed to Nuclei |
| Tag validation | `Port`s with tags that map to zero templates are skipped |
| Unknown services | Scanned with fallback tags if `scan_unknown_services=true`; otherwise skipped |
| `port_hints` | Used when Nmap service detection fails but port is well-known |

## API Equivalents

| Action | API Call |
|--------|----------|
| Create scan | `POST /api/scans` (body: `{ "config_id": "<uuid>" }`) |
| Start scan | `POST /api/scans/{id}/start` |
| List scans | `GET /api/scans` |
| Scan details | `GET /api/scans/{id}` |
| Get ports | `GET /api/scans/{id}/ports` |
| Get vulnerabilities | `GET /api/scans/{id}/vulnerabilities` |
| List comparable scans | `GET /api/scans/{id}/comparable` |
| Compare two scans | `POST /api/comparisons/compare` |

## Related Documentation

- **Scan lifecycle**: [`scan-lifecycle.md`](scan-lifecycle.md) — End-to-end flow
- **Troubleshooting**: [`troubleshooting.md`](troubleshooting.md) — Common issues
- **NucleiProfile mapping**: [`tools/nuclei.md`](tools/nuclei.md) — Service profiles, scan modes
