# Troubleshooting

Common scanning issues and what to check.

## Nmap Shows Open Ports but No Nuclei Findings

| Check | Description |
|-------|-------------|
| `scan_mode` | `fast` mode uses targeted HTTP tags; `deep` mode is comprehensive |
| `nuclei_severity` | Ensure it includes the severities you expect (e.g., `low,info`) |
| Exclusions | `excluded_templates` in `nuclei_profiles.yaml` may filter templates |
| Tag validation | `Port`s with tags that map to zero templates are skipped (warning in Worker logs) |
| `NucleiProfile` | Ensure service is covered in `nuclei_profiles.yaml` or allowed via fallback |
| `enable_nuclei` | Verify Nuclei is enabled in `ScanConfig` |

**Inspect**: `ToolExecution` and `Vulnerability` records in DB to confirm Nuclei ran.

## LOW/INFO Findings Missing in UI

1. Ensure `ScanConfig.nuclei_severity` includes `low,info`
2. For HTTP `fast` mode, verify tags used cover templates that emit LOW/INFO
3. `deep` mode is more likely to find informational findings
4. Confirm `GET /api/scans/{id}/vulnerabilities` returns those severities

## Nuclei Scans Are Slow or Heavy

| Mitigation | Description |
|------------|-------------|
| Use `scan_mode=fast` | Targeted HTTP tags vs comprehensive |
| Check `rate_limit` | Some profiles throttle to 50; default is 150 |
| Reduce template scope | Use tags or custom templates |
| Review `excluded_templates` | Add noisy templates to exclusions |
| Adjust timeouts | `nuclei_timeout`, `global_tool_timeout_seconds` |

## Some Services Are Never Scanned by Nuclei

| Check | Description |
|-------|-------------|
| `NucleiProfile` exists | Verify profile in `nuclei_profiles.yaml` |
| `scan_unknown_services` | Set to `true` for fallback tags on unknown services |
| Tag validation | Tags may map to zero templates (skipped with warning) |
| Exclusions | May remove relevant templates |
| Nmap detection | Verify `Port.service_name`/`product` is populated |
| `port_hints` | Used when Nmap service detection fails |

## Where to Look

| Source | What to Check |
|--------|---------------|
| Worker logs | Tag validation warnings, exclusions, Nuclei command info |
| `tool_executions` table | `raw_output`, `error_message`, `command_line`, `port_id` |
| `vulnerabilities` table | Stored findings with severity |
| `ports` table | `service_name`, `product`, `version`, `state` |
| API | `GET /api/scans/{id}`, `GET /api/scans/{id}/ports`, `GET /api/scans/{id}/vulnerabilities` |

## Docker Desktop Networking (macOS)

**Issue**: Nmap `-sS` (SYN scan) shows ports as `filtered` instead of `open`.

**Cause**: Docker Desktop runs in a VM; raw packets don't survive NAT translation.

**Fix**: Use `-sT` (TCP connect scan) in `nmap_args`:

```json
["-sT", "-sV", "-sC", "-T2", "-Pn"]
```

## Tool-Specific Issues

### httpx Not Running
- Check `enable_httpx` is true in config
- httpx requires HTTP-capable ports (80, 443, 8080, etc.)

### Katana Not Finding Endpoints
- Check `enable_katana` is true in config
- Katana depends on httpx finding live HTTP services
- Adjust `katana_max_depth` for deeper crawling

### testssl.sh Timeouts
- testssl.sh can take 2-5 minutes per host
- Check `testssl_timeout` setting
- Use `enable_testssl=false` for faster scans

### ZAP Connection Issues
- ZAP runs as a Docker container on port 8090
- Ensure `zap` service is running: `docker-compose ps zap`
- Check ZAP logs: `docker-compose logs zap`

## Related Documentation

- **Scan lifecycle**: [`scan-lifecycle.md`](scan-lifecycle.md) — All 12 phases explained
- **Tool documentation**: [`tools/`](tools/) — Individual tool guides
- **Backend**: [`backend.md`](backend.md) — Celery tasks, parsers
