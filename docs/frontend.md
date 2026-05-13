# Frontend

After reading this you'll understand:
- Where the UI lives and the main libraries it uses.
- The config-centric architecture where configs contain targets.
- The key pages (configs, scans, comparisons) and what they show.
- How the UI calls the Backend APIs.

## Stack & Layout

| Aspect | Details |
|--------|---------|
| Location | `frontend/` |
| Frameworks | React + Vite, TypeScript |
| Data fetching | @tanstack/react-query |
| Routing | @tanstack/react-router |
| Styling | Tailwind CSS, Headless UI |

**Key directories**:
- `src/pages/` -- Views
- `src/api/` -- API clients
- `src/components/` -- Shared UI components

## Config-Centric Architecture

The frontend follows the config-centric model:

1. **Configs define targets**: Users create/edit configs with target IPs/hostnames
2. **Scans are executions**: Starting a scan creates a run with auto-incremented `run_number`
3. **Run history**: Scan detail page shows dropdown of all runs for that config
4. **Comparisons**: Only scans from the same config can be compared

## Key Pages

### Dashboard (`src/pages/Dashboard.tsx`)

- **Stats Overview**: 6 stat cards in 2 rows (scans, vulnerabilities, critical vulns, ports, configs, schedules)
- **Status Panels**: Scan status summary, vulnerability severity breakdown, quick actions
- **Insights Widgets**:
  - Top Vulnerable Hosts: Top 5 hosts by vulnerability count with critical badge
  - Services Breakdown: Bar chart of discovered services (http, ssh, mysql, etc.)
  - 7-Day Activity: Sparkline showing scan activity trend
- **Recent Scans Table**: Last 5 scans with links to detail pages
- Auto-refreshes every 30 seconds via `@tanstack/react-query`

### Config Management (`src/pages/Configs.tsx`)

- Lists and edits `ScanConfig` records
- **Targets**: JSON array of IPs/hostnames to scan
- **Tool Toggles**: Control which tools run in each scan
- **Tool Settings**: Per-tool timeouts and options
- **Scheduling**: `schedule` (cron), `schedule_enabled`
- **Edit confirmation**: Saving changes prompts a confirm dialog warning that the config's hash will change and prior scans on this config will no longer be comparable to future runs.

#### Tool Toggles

| Toggle | Tool | Default |
|--------|------|---------|
| `enable_httpx` | httpx HTTP probing | true |
| `enable_katana` | Katana endpoint discovery | true |
| `enable_ssh_audit` | SSH security analysis | true |
| `enable_nuclei` | Nuclei per-port scanning | true |
| `enable_nuclei_endpoints` | Nuclei endpoint scanning | true |
| `enable_nse` | Nmap NSE scripts | true |
| `enable_sslscan` | Quick TLS analysis | true |
| `enable_testssl` | Deep TLS analysis | true |
| `enable_nikto` | Web server scanning | true |
| `enable_zap` | OWASP ZAP scanning | true |

#### Tool Settings

| Setting | Description |
|---------|-------------|
| `scan_mode` | `fast` or `deep` |
| `nuclei_severity` | Filter: `critical,high,medium,low,info` |
| `nuclei_timeout` | Nuclei per-target timeout |
| `httpx_timeout` | HTTP request timeout |
| `httpx_tech_detect` | Enable technology detection |
| `httpx_screenshots` | Capture webpage screenshots |
| `httpx_vhost_discovery` | Virtual host discovery |
| `katana_max_depth` | Maximum crawl depth |
| `nikto_timeout` | Nikto execution timeout |
| `zap_timeout` | ZAP scan timeout |

### New Scan (`src/pages/NewScan.tsx`)

- Selects a config (which contains targets)
- Optionally overrides name/description
- Uses `scansApi.create` then `scansApi.start` to queue the scan
- Targets are automatically copied from the selected config

### Scan List (`src/pages/Scans.tsx`)

- Lists scans with status filter
- Shows `run_number` and config name
- Actions: start, cancel, delete
- Shows `status`, `current_phase`, counts of open ports/vulns

### Scan Detail (`src/pages/ScanDetail.tsx`)

- **Run History Dropdown**: Switch between runs of the same config — labels rendered as `Run #N — <date>` to match the compare-modal dropdown
- **`config_hash` badge**: Short hash badge near the scan header so users can eyeball whether two scans are comparable before opening the compare modal
- **Summary**: `ScanTarget`s, `Port`s, `Vulnerability` counts
- **Phase timeline**: All 12 phases with progress indicators
- **Ports table**: IP, device, port, protocol, `service_name`, version, state, `discovered_by`
- **HTTP Results tab**: httpx probing results with tech detection
- **Endpoints tab**: Discovered endpoints from Katana
- **TLS Results tab**: sslscan and testssl.sh findings
- **Vulnerabilities section**: All severities (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- **Compare button**: Opens the compare modal; dropdown is sourced from `GET /api/scans/{id}/comparable` so only scans with a matching `config_hash` are selectable. Mutation errors are surfaced (no silent failure).

#### Phase Progress

| Phase | Progress |
|-------|----------|
| Port Discovery | 0-10% |
| Service Detection | 10-75% |
| HTTP Probing | 75-78% |
| Endpoint Discovery | 78-80% |
| SSH Audit | 80-85% |
| Nuclei Per-Port | 85-88% |
| Nuclei Endpoints | 88-91% |
| NSE Scripts | 91-93% |
| SSLScan | 93-95% |
| testssl.sh | 95-97% |
| Nikto | 97-98% |
| ZAP | 98-100% |

### Comparison View (`src/pages/ComparisonView.tsx`)

- **Same-`config_hash` only**: Can only compare scans whose `config_hash` matches. Editing a config after a scan invalidates comparability with prior runs.
- **Chronological auto-swap**: If the user picks scans out of order in the compare modal, the API swaps baseline/current so the diff is always older → newer.
- **Enriched output**: Shows version, product, associated vulnerabilities for changed ports
- **Change cards**: New ports, removed ports, changed services, new/resolved vulnerabilities
- **JSON references**: Parsed and displayed as clickable links

## API Integration

### Scans API (`src/api/scans.ts`)

| Function | Description |
|----------|-------------|
| `create` | Create scan from config (auto-assigns `run_number`) |
| `start`, `restart`, `cancel` | Control scan execution |
| `list`, `get` | Retrieve scans |
| `getComparable` | Get same-config scans for comparison selection |
| `getPorts` | Get `Port` records for a scan |
| `getHttpxResults` | Get httpx probing results |
| `getDiscoveredEndpoints` | Get Katana endpoint discovery results |
| `getSSHAudits` | Get SSH audit results |
| `getSslScanResults` | Get sslscan TLS analysis results |
| `getTestsslResults` | Get testssl.sh deep TLS results |
| `getNseFindings` | Get Nmap NSE script results |
| `getVulnerabilities` | Get `Vulnerability` records (Nuclei, Nikto, ZAP) |

### Configs API (`src/api/configs.ts`)

| Function | Description |
|----------|-------------|
| `list`, `get`, `create`, `update`, `delete` | CRUD for `ScanConfig` |
| `setDefault` | Set default config |

**Key fields**:
- Targets: `targets` (JSON array)
- Tool toggles: `enable_httpx`, `enable_katana`, `enable_ssh_audit`, `enable_nuclei`, `enable_nuclei_endpoints`, `enable_nse`, `enable_sslscan`, `enable_testssl`, `enable_nikto`, `enable_zap`
- Nuclei settings: `nuclei_severity`, `nuclei_templates`, `nuclei_timeout`
- httpx settings: `httpx_timeout`, `httpx_tech_detect`, `httpx_screenshots`, `httpx_vhost_discovery`
- Other settings: `scan_mode`, `katana_max_depth`, `nikto_timeout`, `zap_timeout`
- Scheduling: `schedule`, `schedule_enabled`

### Comparisons API (`src/api/comparisons.ts`)

| Function | Description |
|----------|-------------|
| `compare` | Generate enriched diff between two same-config scans |

### Stats API (`src/api/stats.ts`)

| Function | Description |
|----------|-------------|
| `getDashboard` | Aggregated dashboard statistics |

**DashboardStats fields**:
- `total_scans`, `total_vulnerabilities`, `total_ports`, `total_configs`
- `scans_by_status`: Count per status (running, completed, failed, etc.)
- `vulnerabilities_by_severity`: Count per severity level
- `active_schedules`, `next_scheduled_run`: Scheduled scan info
- `top_vulnerable_hosts`: Top 5 hosts with vulnerability/critical counts
- `services_breakdown`: Top 10 discovered services by count
- `scans_by_day`: Last 7 days of scan activity
- `recent_scans`: Last 5 scans with metadata

### Typical UI Flow

1. Create/edit config with targets -> `POST/PATCH /api/configs`
2. Select config and start scan -> `POST /api/scans` (auto-assigns `run_number`)
3. Start scan -> `POST /api/scans/{id}/start`
4. Poll scan status -> `GET /api/scans/{id}`
5. When running/completed:
   - Fetch ports -> `GET /api/scans/{id}/ports`
   - Fetch vulnerabilities -> `GET /api/scans/{id}/vulnerabilities`
6. Compare runs -> `POST /api/comparisons/compare` (validates same `config_id`)

## UI Features

### Run History Dropdown
Located on scan detail page, allows switching between runs of the same config:
- Shows `run_number` and date
- Enables quick navigation between runs
- Only shows scans for the same `config_id`

### Enriched Comparison View
Port and vulnerability changes display:
- **Version/Product**: Shows before/after for service changes
- **Associated Vulnerabilities**: Lists vulns for changed ports
- **Matched At**: Shows where vulnerabilities were detected

## Modifying UI

| Change | Where to Look |
|--------|---------------|
| Dashboard widgets | `src/pages/Dashboard.tsx` |
| Config form with targets | `src/pages/ConfigEdit.tsx` |
| Run history dropdown | `src/pages/ScanDetail.tsx` |
| Comparison view | `src/pages/ComparisonView.tsx` |
| Change cards | `src/components/ChangeCard.tsx` |
| Vulnerability rendering | `src/pages/ScanDetail.tsx` |

## Related Documentation

- **Backend**: [`backend.md`](backend.md) -- Celery tasks, parsers
- **Scan lifecycle**: [`scan-lifecycle.md`](scan-lifecycle.md) -- End-to-end flow
- **Data model**: [`data-model.md`](data-model.md) -- Entity relationships
- **Diagram**: [`mermaid/frontend-flow.mmd`](mermaid/frontend-flow.mmd)
