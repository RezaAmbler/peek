# Codebase Tour

After reading this you'll understand:
- The top-level directory layout and what lives where.
- How Backend, Worker, and Frontend interact.
- Where key logic (tasks, parsers, services, models, tools) resides.
- Where to start reading as a new developer.

## Top-Level Layout

| Directory | Purpose |
|-----------|---------|
| `backend/` | FastAPI app + Celery Worker + models/parsers/tools/services |
| `frontend/` | React/Vite UI that calls the Backend APIs |
| `backend/config/` | Runtime configs (e.g., `nuclei_profiles.yaml`) |
| `data/` | Runtime DB (SQLite) and assets |
| `docs/` | Documentation and diagrams (`docs/mermaid/`) |
| `docker/`, `docker-compose.yml` | Container/devops assets |
| `tests/` | Automated tests |

## Backend Layout (`backend/app/`)

| Directory | Purpose |
|-----------|---------|
| `main.py` | FastAPI entrypoint and router wiring |
| `routers/` | API endpoints (auth, scans, configs, reports, comparisons, scheduled_scans) |
| `tasks/` | Celery tasks for scan orchestration (`scan_tasks.py`) and scheduling |
| `tools/` | Wrappers for 11 external tools (Nmap, httpx, Katana, ssh-audit, Nuclei, NSE, sslscan, testssl, Nikto, ZAP, masscan) |
| `parsers/` | Parse tool outputs into DB models (10 parsers) |
| `services/` | Shared logic (`service_profile.py` for `NucleiProfile` mapping) |
| `models/` | SQLAlchemy models (`Scan`, `ScanTarget`, `Port`, `ToolExecution`, `Vulnerability`, `ScanConfig`, `HttpxResult`, `DiscoveredEndpoint`, `SSHAudit`, `SslScanResult`, `TestsslResult`, `NseFinding`) |
| `schemas/` | Pydantic schemas for API payloads/configs |
| `core/` | Settings (`config.py`), security helpers, DB session helpers |

## Frontend Layout (`frontend/src/`)

| Directory | Purpose |
|-----------|---------|
| `pages/` | Views (NewScan, ScanEdit, Scans list, ScanDetail, Configs) |
| `api/` | API clients (scans, configs, comparisons) |
| `components/` | Shared UI elements (Navigation, cards) |

**Stack**: React + Vite + TypeScript, @tanstack/react-query, @tanstack/react-router, Tailwind/Headless UI

## Backend–Worker–Frontend Interaction

1. **Frontend** calls Backend APIs (create/start/cancel scans; fetch scan, ports, vulnerabilities)
2. **Backend** schedules Celery tasks; Worker executes Nmap → `NucleiProfile` mapping → Nuclei (per port) → parsers write to DB
3. **Frontend** polls scan status and fetches `Port`s/`Vulnerability` records to render results (including LOW/INFO)

## Where Major Logic Lives

| Logic | Location |
|-------|----------|
| Orchestration | `backend/app/tasks/scan_tasks.py` (12-phase pipeline) |
| `NucleiProfile` mapping | `backend/app/services/service_profile.py` + `backend/config/nuclei_profiles.yaml` |
| Tool wrappers | `backend/app/tools/` (11 tools: nmap, httpx, katana, ssh_audit, nuclei, nmap_nse, sslscan, testssl, nikto, zap, masscan) |
| Parsers | `backend/app/parsers/` (10 parsers) |
| Data models | `backend/app/models/` (12 models) |
| API | `backend/app/routers/` |
| Frontend API clients | `frontend/src/api/` |
| Frontend views | `frontend/src/pages/` (ScanDetail for results, NewScan for creation) |

## Suggested Reading Order (New Developer)

1. [`docs/README.md`](README.md), [`docs/architecture.md`](architecture.md), [`docs/scan-lifecycle.md`](scan-lifecycle.md) — Context and diagrams
2. `backend/app/tasks/scan_tasks.py` — Orchestration phases
3. `backend/app/services/service_profile.py` + `backend/config/nuclei_profiles.yaml` — `NucleiProfile` mapping/modes/exclusions
4. `backend/app/tools/` and `backend/app/parsers/` — Tool invocation and parsing
5. `backend/app/models/` and [`docs/data-model.md`](data-model.md) — Persistence
6. `frontend/src/pages/ScanDetail.tsx` and `frontend/src/pages/NewScan.tsx` — UI flows

## Related Documentation

- **Architecture**: [`architecture.md`](architecture.md)
- **Scan lifecycle**: [`scan-lifecycle.md`](scan-lifecycle.md) — All 12 phases
- **Tool documentation**: [`tools/`](tools/) — Individual tool guides (11 tools)
- **Data model**: [`data-model.md`](data-model.md)
- **Extending scanners**: [`extending-scanners.md`](extending-scanners.md)
