# Frontend

After reading this you'll understand:
- Where the UI lives and the main libraries it uses.
- The key pages (create/edit scan, list, detail) and what they show.
- How the UI calls the Backend APIs for scans, ports, and vulnerabilities.
- Where to start if you need to change Nuclei-related presentation.

## Stack & Layout

| Aspect | Details |
|--------|---------|
| Location | `frontend/` |
| Frameworks | React + Vite, TypeScript |
| Data fetching | @tanstack/react-query |
| Routing | @tanstack/react-router |
| Styling | Tailwind CSS, Headless UI |

**Key directories**:
- `src/pages/` — Views
- `src/api/` — API clients
- `src/components/` — Shared UI components

## Key Pages

### Scan Creation (`src/pages/NewScan.tsx`)

- Lets users provide name, description, `config_id`, targets (manual or CSV)
- Uses `scansApi.create` then `scansApi.start` to queue the scan
- Relies on selected `ScanConfig` for `scan_mode` and Nuclei settings

### Scan Edit (`src/pages/ScanEdit.tsx`)

- Edit pending scans (name/description/targets/config)

### Scan List (`src/pages/Scans.tsx`)

- Lists scans with status filter
- Actions: start, cancel, delete
- Shows `status`, `current_phase` (including `nuclei`), counts of open ports/vulns

### Scan Detail (`src/pages/ScanDetail.tsx`)

- **Summary**: `ScanTarget`s, `Port`s, `Vulnerability` counts
- **Phase timeline**: `nmap_discovery`, `nmap`, `ssh_audit`, `nuclei`, `completed`
- **Ports table**: IP, device, port, protocol, `service_name`, version, state, `discovered_by`
- **Vulnerabilities section**: All severities (CRITICAL/HIGH/MEDIUM/LOW/INFO) if they exist
- LOW/INFO visibility: Results show whatever severities the Backend returned based on `nuclei_severity`

### Configs (`src/pages/Configs.tsx`)

- Lists and edits `ScanConfig` records
- Fields: `enable_nuclei`, `nuclei_severity`, `nuclei_timeout`, `nuclei_templates`
- Note: `scan_mode` is supported by Backend; Frontend API client may need extension to expose it

## API Integration

### Scans API (`src/api/scans.ts`)

| Function | Description |
|----------|-------------|
| `create`, `createFromCSV` | Create new scan |
| `start`, `restart`, `cancel` | Control scan execution |
| `list`, `get` | Retrieve scans |
| `getPorts` | Get `Port` records for a scan |
| `getSSHAudits` | Get SSH audit results |
| `getVulnerabilities` | Get `Vulnerability` records |

### Configs API (`src/api/configs.ts`)

| Function | Description |
|----------|-------------|
| `list`, `get`, `create`, `update`, `delete` | CRUD for `ScanConfig` |
| `setDefault` | Set default config |

**Fields include**: `enable_nuclei`, `nuclei_severity`, `nuclei_templates`, `nuclei_timeout`

### Typical UI Flow

1. Create scan → call `POST /api/scans`
2. Start scan → call `POST /api/scans/{id}/start`
3. Poll scan status → `GET /api/scans/{id}`
4. When running/completed:
   - Fetch ports → `GET /api/scans/{id}/ports`
   - Fetch vulnerabilities → `GET /api/scans/{id}/vulnerabilities`
5. Display results including LOW/INFO severities

## Modifying Nuclei-Related UI

| Change | Where to Look |
|--------|---------------|
| Vulnerability rendering | `src/pages/ScanDetail.tsx` |
| Severity toggles | `src/pages/ScanDetail.tsx` |
| Ports/services display | `ScanDetail` ports table |
| Expose `scan_mode` | Extend `src/api/configs.ts` types and `Configs` form |

## Related Documentation

- **Backend**: [`backend.md`](backend.md) — Celery tasks, parsers
- **Scan lifecycle**: [`scan-lifecycle.md`](scan-lifecycle.md) — End-to-end flow
- **Usage guide**: [`usage-guide.md`](usage-guide.md) — Running scans
- **Diagram**: [`mermaid/frontend-flow.mmd`](mermaid/frontend-flow.mmd)
