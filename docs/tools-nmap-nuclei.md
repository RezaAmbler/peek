# Nmap & Nuclei Deep Dive

After reading this you'll understand:
- How Nmap discovery and service detection are invoked and parsed.
- How `get_nuclei_profile()` + `nuclei_profiles.yaml` map services/products to Nuclei targets/tags.
- How Nuclei commands are built per port and how findings flow into the DB (including LOW/INFO).

## Nmap

### Discovery (`tools/nmap.py` → `run_nmap_discovery`)

```bash
nmap --top-ports <N> -Pn -sT -T* --open -oX <output.xml> <targets>
```

- Scans top ports with `-Pn -sT -T* --open`
- Writes XML output
- Parsed by `parsers/nmap_discovery_parser.py` → creates `Port` rows (`state=open`)

### Service Detection (`tools/nmap.py` → `run_nmap`)

```bash
nmap -sT -sV -sC -T2 -Pn -p <ports> -oX <output.xml> <targets>
```

- Runs with configured `nmap_args` from `ScanConfig`
- Writes XML output
- Parsed by `parsers/nmap_parser.py` → updates `Port` with:
  - `service_name` (e.g., `http`, `ssh`, `ssl/http`)
  - `product` (e.g., `Apache httpd`, `OpenSSH`)
  - `version` (e.g., `2.4.41`, `8.2p1`)
  - `extra_info` (NSE script snippets)

## NucleiProfile Mapping

**Module**: `backend/app/services/service_profile.py`
**Config**: `backend/config/nuclei_profiles.yaml`

### Profile Fields

| Field | Description | Example |
|-------|-------------|---------|
| `should_scan` | Whether to scan this service | `true` |
| `target_format` | `url` or `host_port` | `url` for HTTP |
| `protocol` | `http`, `https`, or `None` | `https` for SSL services |
| `tags` | Nuclei template tags | `[ssh, network]` or `[]` for comprehensive |
| `timeout_multiplier` | Scales `nuclei_timeout` | `0.5` for fast services |
| `rate_limit` | Optional per-profile rate limit | `50` for databases |

### How Profiles Are Selected

1. Normalize `service_name` (lowercase, handle `ssl/` prefix)
2. Look up in `service_profiles` section of YAML
3. If not found and `scan_unknown_services=true`, use fallback tags `[service_name, network]`
4. Add product-specific tags from `product_tags` section based on substring match
5. Apply `scan_mode` for HTTP services:
   - `fast`: Use `scan_modes.fast.http_tags` + product tags
   - `deep`: Use empty tags (comprehensive)

### Target Building

`build_nuclei_target(ip, port, profile)` returns:
- **URL format**: `http://ip:port` or `https://ip:port` (port omitted for 80/443)
- **Host:port format**: `ip:port`

### Tag Validation

`validate_tags(tags)` runs:

```bash
nuclei -tl -tags <tag1,tag2,...>
```

Returns `(has_templates: bool, template_count: int)`. `Port`s with tags that resolve to zero templates are skipped.

### Exclusions

`excluded_templates` from YAML are passed to Nuclei as `-exclude-templates <pattern>`.

## Nuclei Invocation

One Nuclei process per scannable `Port`. Command pattern:

```bash
nuclei -target <target> \
       -severity <nuclei_severity> \
       -jsonl-export <tmp_file> \
       -silent -no-color -no-interactsh \
       -rate-limit <profile.rate_limit or 150> \
       [-tags <tags>] \
       [-templates <path>] \
       [-exclude-templates <pattern>]
```

### Flag Details

| Flag | Source | Notes |
|------|--------|-------|
| `-target` | `build_nuclei_target()` | URL or host:port |
| `-severity` | `ScanConfig.nuclei_severity` | Default: `critical,high,medium,low,info` |
| `-rate-limit` | `NucleiProfile.rate_limit` or 150 | Per-profile override |
| `-tags` | `NucleiProfile.tags` | Omitted if empty (comprehensive) |
| `-templates` | `ScanConfig.nuclei_templates` | Optional override |
| `-exclude-templates` | `nuclei_profiles.yaml` | Global exclusions |

### Scan Mode Behavior

| Mode | HTTP Tags | Non-HTTP Tags |
|------|-----------|---------------|
| `fast` | `scan_modes.fast.http_tags` + product tags | Service tags (e.g., `[ssh, network]`) |
| `deep` | Empty (comprehensive) | Service tags |

## Parsing and Storage

1. Nuclei writes JSONL output
2. `parsers/nuclei_parser.py` parses each line
3. Creates `Vulnerability` records with:
   - `template_id`, `name`, `severity`, `vuln_type`
   - `matched_at`, `host`, `port`
   - `tags`, `references`
   - Links to `ScanTarget`, `ToolExecution`, and `Port` (via `port_id`)
4. Severity is stored as reported by Nuclei (CRITICAL, HIGH, MEDIUM, LOW, INFO)

## Debugging Tips

| Issue | What to Check |
|-------|---------------|
| Nuclei not running | Check `enable_nuclei` in `ScanConfig` |
| No findings | Check `nuclei_severity`, `excluded_templates`, tag validation warnings |
| Service not scanned | Verify `NucleiProfile` exists or `scan_unknown_services=true` |
| Slow scans | Use `scan_mode=fast`, check `rate_limit`, reduce template scope |

**Where to look**:
- `tool_executions` table: `raw_output`, `error_message`, `command_line`, `port_id`
- `ports` table: `service_name`, `product`, `version`
- Worker logs: Tag validation warnings, exclusions applied

## Related Documentation

- **Scan lifecycle**: [`scan-lifecycle.md`](scan-lifecycle.md) — End-to-end flow
- **Data model**: [`data-model.md`](data-model.md) — Entity relationships
- **Backend**: [`backend.md`](backend.md) — Celery tasks, parsers
- **Troubleshooting**: [`troubleshooting.md`](troubleshooting.md) — Common issues
