# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PEEK V2 (Port Enumeration & Evaluation Kit) is a network security scanner with historical comparison capabilities. It discovers open ports, identifies services, and runs vulnerability scans using Nmap, Nuclei, ssh-audit, and other security tools.

## Technology Stack

| Layer | Technologies |
|-------|-------------|
| Backend | FastAPI 0.109, SQLAlchemy 2.0 (async), Celery 5.3, Pydantic 2.5 |
| Database | SQLite + aiosqlite (WAL mode) |
| Frontend | React 18, TypeScript 5.3, Vite 5, TanStack Router/Query, Zustand, Tailwind CSS 3.4 |
| Auth | JWT (python-jose, bcrypt) - 7-day tokens, HS256 |
| Queue | Redis 7 + Celery |

## Development Commands

### Docker (Full Stack)
```bash
docker-compose up -d              # Start all services
docker-compose down               # Stop all services
docker-compose logs -f celery     # Follow Celery worker logs
docker-compose logs -f backend    # Follow API logs
```

### Backend Development
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload     # Start API server (port 8000)
```

### Celery Worker (Required for Scans)
```bash
cd backend
celery -A app.celery_app worker --loglevel=info   # Start worker
celery -A app.celery_app beat --loglevel=info     # Start scheduler
```

### Frontend Development
```bash
cd frontend
npm install
npm run dev                       # Start dev server (port 3000)
npm run build                     # Production build
```

## Architecture

### Components
- **Backend API** (FastAPI): REST endpoints at `backend/app/routers/`, models at `backend/app/models/`
- **Celery Worker**: Executes scan phases at `backend/app/tasks/scan_tasks.py`
- **Celery Beat**: Runs scheduled scans at `backend/app/tasks/scheduled_scan_tasks.py`
- **Frontend** (React/Vite): UI at `frontend/src/pages/`, API clients at `frontend/src/api/`
- **Redis**: Message broker for Celery

### Scan Pipeline Flow
1. API creates `Scan` and `ScanTarget` records
2. Worker runs Nmap discovery → creates `Port` rows
3. Worker runs Nmap service detection → updates `Port` with service info
4. Worker runs ssh-audit (optional) on SSH ports
5. Worker runs Nuclei per-port using `NucleiProfile` mapping → creates `Vulnerability` records
6. Worker runs optional phases: NSE scripts, SSLscan, Nikto, ZAP

### Key Files for Scan Logic
| Purpose | Location |
|---------|----------|
| Scan orchestration | `backend/app/tasks/scan_tasks.py` |
| Scheduled scans | `backend/app/tasks/scheduled_scan_tasks.py` |
| NucleiProfile mapping | `backend/app/services/service_profile.py` |
| Tool wrappers | `backend/app/tools/` (nmap.py, nuclei.py, ssh_audit.py, sslscan.py, nikto.py) |
| Output parsers | `backend/app/parsers/` (nmap_parser.py, nuclei_parser.py, etc.) |
| Data models | `backend/app/models/` (scan.py, port.py, vulnerability.py, scheduled_scan.py) |

### Data Model Relationships
```
Scan → ScanTarget → Port → Vulnerability
                  → ToolExecution → Vulnerability
                  → SSHAudit
                  → SslScanResult
                  → NseFinding
     → ScanConfig
     → ScanComparison (baseline diff)

ScheduledScan → triggers Scan (via cron)
```
- `Port`: open port with `service_name`, `product`, `version`
- `ToolExecution`: one run of Nmap/Nuclei/ssh-audit with `command_line`, `raw_output`
- `Vulnerability`: finding linked to `ScanTarget`, `ToolExecution`, and `Port`
- `SSHAudit`: SSH hardening assessment results
- `SslScanResult`: SSL/TLS security assessment
- `NseFinding`: Nmap scripting engine results

## API Endpoints Quick Reference

| Endpoint | Purpose |
|----------|---------|
| `GET /api/health` | Health check |
| `POST /api/auth/login` | JWT authentication |
| `GET/POST /api/scans` | List/create scans |
| `POST /api/scans/{id}/start` | Queue scan for execution |
| `POST /api/scans/{id}/cancel` | Cancel running scan |
| `GET /api/scans/{id}/ports` | List discovered ports |
| `GET /api/scans/{id}/vulnerabilities` | List findings |
| `GET/POST /api/configs` | Scan configuration profiles |
| `GET/POST /api/comparisons` | Historical scan comparison |
| `GET /api/reports/{id}/pdf\|html\|csv` | Export reports |
| `GET/POST /api/scheduled-scans` | Recurring scan schedules |

Swagger docs available at `/docs` when backend is running.

## Frontend Structure

### Routes
- `/login` - Authentication
- `/dashboard` - Overview and stats
- `/scans` - Scan list with filtering
- `/scans/new` - Create new scan
- `/scans/$scanId` - Scan detail with results
- `/configs` - Scan configuration management
- `/scheduled-scans` - Recurring scan schedules
- `/admin/users` - User management (admin only)

### State Management
- **Zustand**: Auth state (`frontend/src/hooks/useAuth.ts`)
- **TanStack Query**: Server state and caching
- **API clients**: `frontend/src/api/` (scans.ts, configs.ts, etc.)

## External Tool Dependencies

Scans require these tools installed in the Celery worker environment:
- **nmap**: Port discovery and service detection
- **nuclei**: Vulnerability scanning (uses templates)
- **ssh-audit**: SSH configuration analysis
- **sslscan**: SSL/TLS security assessment (optional)
- **nikto**: Web server scanning (optional)
- **masscan**: Fast port discovery (optional)
- **OWASP ZAP**: Web application security testing (optional, runs on port 8090)

## Configuration

- **Nuclei profiles**: `config/nuclei_profiles.yaml` - service-to-tag mappings, scan modes, exclusions
- **NSE profiles**: `config/nse_profiles.yaml` - Nmap scripting engine configurations
- **SSL config**: `config/sslscan_config.yaml` - SSL scan parameters
- **Scan settings**: `ScanConfig` model controls `nuclei_severity`, `scan_mode` (fast/deep), timeouts
- **Environment**: Copy `.env.example` to `backend/.env`

## Authentication

- **JWT tokens**: 7-day expiry, HS256 algorithm
- **Default dev credentials**: `admin` / `admin` (auto-created on first startup)
- **Header**: `Authorization: Bearer <token>`
- **User roles**: Regular users see own scans; admins can manage all users

## Services (Docker)

| Service | Port | Purpose |
|---------|------|---------|
| frontend | 3000 | React UI (Nginx in prod) |
| backend | 8000 | FastAPI + Swagger docs at /docs |
| celery | - | Scan worker |
| celery-beat | - | Scheduled scan scheduler |
| redis | 6379 | Celery broker |
| zap | 8090 | OWASP ZAP (optional) |

## Deployment

Production deployment files in `deploy/`:
- `deploy/deploy.sh` - Production deployment script
- `deploy/setup-host.sh` - Host environment setup
- `docker-compose.prod.yml` - Production configuration

Database stored at `./data/peek.db` (SQLite with WAL mode).

## Adding New Scan Tools

1. Create runner in `backend/app/tools/<tool>.py`
2. Create parser in `backend/app/parsers/<tool>_parser.py`
3. Add phase in `backend/app/tasks/scan_tasks.py`
4. Create `ToolExecution` records with appropriate linkage
5. Add model if tool produces structured results (e.g., `SSHAudit`, `SslScanResult`)
