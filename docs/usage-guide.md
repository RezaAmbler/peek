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
4. **Phase timeline**: Indicates where the scan is (`nmap_discovery`, `nmap`, `ssh_audit`, `nuclei`, `completed`)

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
| Create scan | `POST /api/scans` |
| Start scan | `POST /api/scans/{id}/start` |
| List scans | `GET /api/scans` |
| Scan details | `GET /api/scans/{id}` |
| Get ports | `GET /api/scans/{id}/ports` |
| Get vulnerabilities | `GET /api/scans/{id}/vulnerabilities` |

## Related Documentation

- **Scan lifecycle**: [`scan-lifecycle.md`](scan-lifecycle.md) — End-to-end flow
- **Troubleshooting**: [`troubleshooting.md`](troubleshooting.md) — Common issues
- **NucleiProfile mapping**: [`tools-nmap-nuclei.md`](tools-nmap-nuclei.md) — Service profiles
