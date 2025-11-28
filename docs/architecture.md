# Architecture

After reading this you’ll understand:
- The major components (frontend, backend API, Celery/worker, database, external tools).
- How they communicate during a scan.
- Where to look for scan-specific details.

## Components
- **Frontend (React/Vite)**: Creates scans, shows scan progress and results (ports, vulnerabilities including low/info when configured).
- **Backend API (FastAPI)**: Exposes auth, configs, scans, reports; persists models (Scan, ScanTarget, Port, ToolExecution, Vulnerability).
- **Worker (Celery)**: Executes scan phases (Nmap discovery, Nmap service detection, optional ssh-audit, nuclei). Lives in `backend/app/tasks/scan_tasks.py`.
- **Tools**: Nmap, nuclei, ssh-audit invoked by the worker. Service→profile mapping for nuclei lives in `backend/app/services/service_profile.py` with config in `backend/config/nuclei_profiles.yaml`.
- **Database**: Stores scan metadata, ports, tool executions, vulnerabilities, comparisons, etc.

## How they talk
- Frontend calls Backend API to create/start scans.
- Backend schedules work to Celery; worker runs tools and writes results to DB.
- Frontend polls APIs to render ports and vulnerabilities (including low/info severities when `nuclei_severity` includes them).

## Diagram
See the Mermaid source at `docs/mermaid/overview.mmd`. Example inline view:

```mermaid
%% See docs/mermaid/overview.mmd for the source of truth
graph LR
  User --> Frontend
  Frontend --> Backend
  Backend --> Worker
  Worker -->|invokes| Nmap
  Worker -->|invokes| Nuclei
  Worker -->|invokes| "ssh-audit"
  Worker --> DB
  DB --> Backend --> Frontend --> User
```

## Next steps
- For the full scan flow, read `scan-lifecycle.md`.
- For mapping details and severities, see the scan lifecycle doc and `backend/config/nuclei_profiles.yaml`.

