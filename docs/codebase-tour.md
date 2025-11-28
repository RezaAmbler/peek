# Codebase Tour

After reading this you’ll understand:
- The top-level directory layout and what lives where.
- How backend, worker, and frontend interact.
- Where key logic (tasks, parsers, services, models, tools) resides.
- Where to start reading as a new developer.

## Top-level layout (high level)
- `backend/`: FastAPI app + Celery worker + models/parsers/tools/services.
- `frontend/`: React/Vite UI that calls the backend APIs.
- `config/` / `backend/config/`: Runtime configs (e.g., `nuclei_profiles.yaml`).
- `data/`: Runtime DB (SQLite) and assets.
- `docs/`: Documentation and diagrams (`docs/mermaid/`).
- `docker/`, `docker-compose.yml`, `dockerfiles`: Container/devops assets.
- `tests/`: Automated tests (if present).

## Backend layout (backend/app/)
- `main.py`: FastAPI entrypoint and router wiring.
- `routers/`: API endpoints (auth, scans, configs, reports, comparisons, scheduled_scans).
- `tasks/`: Celery tasks for scan orchestration (`scan_tasks.py`) and scheduling (`scheduled_scan_tasks.py`).
- `tools/`: Wrappers for external tools (nmap, nuclei, ssh_audit, masscan).
- `parsers/`: Parse tool outputs into DB models (nmap, nuclei, ssh_audit, masscan).
- `services/`: Shared logic (e.g., `service_profile.py` for nuclei profiles/tags, config helpers).
- `models/`: SQLAlchemy models (Scan, ScanTarget, Port, ToolExecution, Vulnerability, ScanConfig, etc.).
- `schemas/`: Pydantic schemas for API payloads/configs.
- `core/`: Settings (`config.py`), security helpers, DB session helpers.

## Frontend layout (frontend/src/)
- `pages/`: Views (NewScan, ScanEdit, Scans list, ScanDetail, Configs, etc.).
- `api/`: API clients (scans, configs, comparisons).
- `components/`: Shared UI elements (Navigation, cards).
- Uses React + Vite + TypeScript, @tanstack/react-query for data fetching, @tanstack/react-router for routing, Tailwind/Headless UI for styling.

## Backend–worker–frontend interaction
- Frontend calls backend APIs (create/start/cancel scans; fetch scan, ports, vulnerabilities).
- Backend schedules Celery tasks; worker executes Nmap → service_profile mapping → nuclei (per port) → parsers write to DB.
- Frontend polls scan status and fetches ports/vulnerabilities to render results (including low/info when emitted).

## Where major logic lives
- Orchestration: `backend/app/tasks/scan_tasks.py` (run_scan, run_nuclei_phase, etc.).
- Profiles/mapping: `backend/app/services/service_profile.py` + `backend/config/nuclei_profiles.yaml` (scan modes, exclusions, tag validation, rate limits).
- Tool wrappers: `backend/app/tools/` (nmap, nuclei, ssh_audit, masscan).
- Parsers: `backend/app/parsers/` (nmap_parser, nuclei_parser, ssh_audit_parser).
- Data models: `backend/app/models/` (Scan/ScanTarget/Port/ToolExecution/Vulnerability/ScanConfig).
- API: `backend/app/routers/` (scans, configs, comparisons, reports).
- Frontend API clients: `frontend/src/api/`.
- Frontend views: `frontend/src/pages/` (notably ScanDetail for results, NewScan for creation).

## Suggested reading order (new dev)
1) `docs/README.md`, `docs/architecture.md`, `docs/scan-lifecycle.md` for context and diagrams.
2) `backend/app/tasks/scan_tasks.py` to see the orchestration phases.
3) `backend/app/services/service_profile.py` + `backend/config/nuclei_profiles.yaml` to understand nuclei mapping/modes/exclusions.
4) `backend/app/tools/` and `backend/app/parsers/` to see how tools are called and parsed.
5) `backend/app/models/` and `docs/data-model.md` for persistence.
6) `frontend/src/pages/ScanDetail.tsx` and `frontend/src/pages/NewScan.tsx` to see how results and creation flow in the UI.

## How backend, worker, and frontend fit together
- Backend API exposes CRUD for scans/configs and result retrieval.
- Celery worker (same codebase) executes scans and writes results.
- Frontend drives user flows and polls the API for status/results.

