# Usage Guide

Practical steps to run scans and read results.

## Run a fast scan on a host or subnet
- In the UI: New Scan → enter targets → select a ScanConfig that uses `scan_mode=fast` and nuclei enabled.
- Fast mode behavior:
  - HTTP services use targeted tags from `scan_modes.fast.http_tags` (nuclei_profiles.yaml) plus product tags.
  - Non-HTTP services still use service tags (ssh, mysql, etc.) validated before running.
  - Exclusions and tag validation apply; ports with no matching templates are skipped with a warning in logs.
  - Severity comes from the config’s `nuclei_severity` (default supports critical..info; adjust as needed).
- Start the scan; progress will show nuclei phase when reached.

## Run a deep scan including low/info
- In the UI: New Scan → pick a ScanConfig with `scan_mode=deep`, nuclei enabled, and `nuclei_severity` including `low,info` (default backend value does).
- Deep mode behavior:
  - HTTP services use empty tags (comprehensive HTTP coverage); non-HTTP use service tags.
  - Exclusions still apply; tag validation still enforced.
  - Low/Info severities from nuclei appear in the vulnerabilities section if emitted.

## View and interpret results
- From the Scan list, open a scan to the Scan Detail page.
- Ports table shows discovered services (service_name/product/version/state/source).
- Vulnerabilities section lists all severities (critical/high/medium/low/info) returned by the backend.
- Phase timeline indicates where the scan is (nmap_discovery, nmap, ssh_audit, nuclei, completed).

## Understand what is (not) scanned by nuclei
- Service profiles (`nuclei_profiles.yaml`) decide which services get scanned and which tags/rate limits apply.
- Exclusions: `excluded_templates` are always passed to nuclei.
- Tag validation: if a profile’s tags map to zero templates (`nuclei -tl -tags ...`), that port is skipped.
- Unknown services: may be scanned with fallback tags if `scan_unknown_services` is true; otherwise skipped.

## API equivalents (quick reference)
- Create/start: `POST /api/scans` then `POST /api/scans/{id}/start`.
- List scans: `GET /api/scans`.
- Scan details: `GET /api/scans/{id}`; ports: `/api/scans/{id}/ports`; vulnerabilities: `/api/scans/{id}/vulnerabilities`.
