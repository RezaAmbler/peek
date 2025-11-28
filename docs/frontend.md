# Frontend

After reading this you’ll understand:
- Where the UI lives and the main libraries it uses.
- The key pages (create/edit scan, list, detail) and what they show.
- How the UI calls the backend APIs for scans, ports, and vulnerabilities.
- Where to start if you need to change nuclei-related presentation.

## Stack & layout
- Location: `frontend/`
- Frameworks/libs: React + Vite, TypeScript, @tanstack/react-query (data fetching), @tanstack/react-router (routing), Tailwind/Headless UI for styling/components.
- Key app code: `src/pages` (views), `src/api` (API clients), `src/components` (shared UI).

## Key pages
- **Scan creation (`src/pages/NewScan.tsx`)**
  - Lets users provide name, description, config_id, targets (manual or CSV).
  - Uses `scansApi.create` then immediately `scansApi.start` to queue the scan.
  - Current UI does not expose `scan_mode` or nuclei-specific overrides; it relies on the selected ScanConfig.
- **Scan edit (`src/pages/ScanEdit.tsx`)**
  - Edit pending scans (name/description/targets/config).
- **Scan list (`src/pages/Scans.tsx`)**
  - Lists scans with status filter; actions: start, cancel, delete.
  - Shows status/current_phase (including nuclei), counts of open ports/vulns.
- **Scan detail (`src/pages/ScanDetail.tsx`)**
  - Shows scan summary (targets, ports, vulnerabilities) and phase timeline (nmap_discovery, nmap, ssh_audit, nuclei).
  - Ports table: IP, device, port, protocol, service_name, version, state, discovered_by.
  - Vulnerabilities section renders all severities (critical/high/medium/low/info) if they exist.
  - Info/low visibility: there’s a toggle for info findings in state; results show whatever severities the backend returned based on config/nuclei_severity.
  - Links to restart/cancel/delete, compare with previous scan, export reports.
- **Configs (`src/pages/Configs.tsx`)**
  - Lists and edits ScanConfigs (enable_nuclei, nuclei_severity, nuclei_timeout, etc.).
  - Note: current UI `configsApi` does not expose `scan_mode`; backend supports it, so adding it would require extending the API client/form.

## API integration (scan-related)
- API client: `src/api/scans.ts`:
  - `create`, `createFromCSV`, `start`, `restart`, `cancel`, `delete`, `list`, `get`.
  - Detail helpers: `getPorts`, `getSSHAudits`, `getVulnerabilities`.
- API client: `src/api/configs.ts`:
  - `list`, `get`, `create`, `update`, `delete`, `setDefault`.
  - Fields include nuclei controls (enable_nuclei, nuclei_severity, nuclei_templates, nuclei_timeout); `scan_mode` is not currently modeled on the frontend.
- Typical UI flow:
  - Create/start scan → poll scan (`GET /api/scans/{id}`) → when running/completed, fetch ports (`/api/scans/{id}/ports`), ssh-audits, vulnerabilities.
  - Vulnerabilities endpoint returns all severities emitted by nuclei (critical..info); UI displays them.

## Modifying nuclei-related UI
- Start with `src/pages/ScanDetail.tsx` for vulnerability rendering and severity toggles.
- Ports/services display: `ScanDetail` ports table.
- Config exposure: extend `src/api/configs.ts` types and `Configs` form if you need to surface `scan_mode` or other nuclei settings.
