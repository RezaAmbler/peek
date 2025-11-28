# Troubleshooting

Common scanning issues and what to check.

## Nmap shows open ports but no nuclei findings
- Check scan_mode: fast mode uses targeted HTTP tags; deep mode is comprehensive.
- Check nuclei_severity: ensure it includes the severities you expect (e.g., low/info).
- Check exclusions: `excluded_templates` in `nuclei_profiles.yaml` may filter out templates.
- Check tag validation: ports with tags that map to zero templates are skipped (warning in worker logs).
- Verify service profiles: ensure the service is covered in `nuclei_profiles.yaml` or allowed via fallback.
- Inspect ToolExecution/Vulnerability records in DB to confirm nuclei ran and what it returned.

## Low/Info findings missing in UI
- Ensure the ScanConfig `nuclei_severity` includes `low,info`.
- For HTTP fast mode, verify tags used still cover templates that emit low/info; deep mode is more likely to find them.
- Confirm vulnerabilities endpoint returns those severities; the Scan Detail page will render any severities present.

## Nuclei scans are slow or heavy
- Use `scan_mode=fast` for targeted HTTP tags; deep mode runs more templates.
- Check profile-specific `rate_limit` (some services throttle to 50); defaults to 150 otherwise.
- Reduce template scope via tags or custom templates; review `excluded_templates`.
- Ensure timeouts (`nuclei_timeout`, `global_tool_timeout_seconds`) are appropriate.

## Some services are never scanned by nuclei
- Verify service profile exists or `scan_unknown_services` is true for fallback tags.
- Tag validation may skip ports if tags have zero templates.
- Exclusions may remove relevant templates; check `excluded_templates`.
- Confirm Nmap service_name/product is present; port_hints are used when service detection fails.

## Where to look
- Worker logs for tag validation warnings, exclusions, and nuclei command info.
- DB tables: `tool_executions` (raw_output/error_message/command_line/port_id), `vulnerabilities`, `ports`.
- API: `GET /api/scans/{id}`, `/api/scans/{id}/ports`, `/api/scans/{id}/vulnerabilities` to verify what was stored.
