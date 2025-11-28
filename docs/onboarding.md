# Developer Onboarding

Welcome to PEEK! This guide will help you get up and running quickly.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.9+ | Backend, Celery Worker |
| Node.js | 18+ | Frontend build |
| Docker | Latest | Container runtime |
| Docker Compose | v2+ | Multi-container orchestration |

**External tools** (included in Docker container):
- Nmap — Port discovery and service detection
- Nuclei — Vulnerability scanning
- ssh-audit — SSH security analysis

## Environment Setup

### Option 1: Docker (Recommended)

```bash
# Clone the repository
git clone <repo-url>
cd PEEK

# Copy environment template
cp .env.example backend/.env

# Start all services
docker-compose up -d

# Verify services are running
docker-compose ps
```

Services:
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

### Option 2: Local Development

#### Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start Redis (Celery broker)
redis-server

# Start FastAPI (in one terminal)
uvicorn app.main:app --reload

# Start Celery worker (in another terminal)
celery -A app.tasks worker --loglevel=info
```

#### Frontend

```bash
cd frontend
npm install
npm run dev
```

## First-Day Tasks

### 1. Run Your First Scan

1. Open the Frontend at http://localhost:3000
2. Login or create an account
3. Go to **New Scan**
4. Enter a target IP or subnet (e.g., `192.168.1.1`)
5. Select a `ScanConfig` (or use default)
6. Click **Start Scan**
7. Watch the phase timeline progress: `nmap_discovery` → `nmap` → `ssh_audit` → `nuclei` → `completed`

### 2. Understand Fast vs Deep Scans

| Mode | HTTP Behavior | Non-HTTP Behavior | Use Case |
|------|---------------|-------------------|----------|
| `fast` | Targeted tags from `scan_modes.fast.http_tags` | Service tags (e.g., `[ssh, network]`) | Quick vulnerability sweep |
| `deep` | Empty tags (comprehensive) | Service tags | Thorough analysis |

To run a deep scan with LOW/INFO findings:
1. Ensure `ScanConfig.nuclei_severity` includes `low,info`
2. Set `scan_mode=deep`

### 3. Explore the Nmap → NucleiProfile → Nuclei Pipeline

1. Nmap discovers open ports → creates `Port` records
2. Nmap service detection → updates `Port` with `service_name`, `product`, `version`
3. `get_nuclei_profile()` decides how to scan each `Port`:
   - Target format (URL vs host:port)
   - Tags for template selection
   - Rate limits and timeouts
4. Nuclei runs per port → creates `Vulnerability` records
5. Frontend displays results

**Key file**: `backend/app/services/service_profile.py`
**Config**: `backend/config/nuclei_profiles.yaml`

### 4. Locate Data in the Database

```sql
-- Find a scan
SELECT id, name, status, current_phase FROM scans LIMIT 5;

-- Get ports for a scan
SELECT p.port, p.service_name, p.product, p.version, p.state
FROM ports p
JOIN scan_targets st ON p.scan_target_id = st.id
WHERE st.scan_id = '<scan_id>';

-- Get vulnerabilities for a scan
SELECT v.name, v.severity, v.host, v.port, v.template_id
FROM vulnerabilities v
JOIN scan_targets st ON v.scan_target_id = st.id
WHERE st.scan_id = '<scan_id>';

-- Get tool executions with port linkage
SELECT te.tool_name, te.port_id, te.exit_code, te.command_line
FROM tool_executions te
JOIN scan_targets st ON te.scan_target_id = st.id
WHERE st.scan_id = '<scan_id>';
```

### 5. Interpret LOW/INFO Results in UI

- `Vulnerability` records include severity as reported by Nuclei (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- UI displays all severities returned by the Backend
- To see LOW/INFO findings:
  1. Ensure `nuclei_severity` in `ScanConfig` includes `low,info`
  2. Use `deep` mode for comprehensive HTTP scanning

### 6. Read the Diagrams

| Diagram | Description | Location |
|---------|-------------|----------|
| System Overview | Top-level component diagram | [`mermaid/system-overview.mmd`](mermaid/system-overview.mmd) |
| Scan Lifecycle | Phase flow diagram | [`mermaid/scan-lifecycle.mmd`](mermaid/scan-lifecycle.mmd) |
| Data Model | Entity relationships | [`mermaid/data-model.mmd`](mermaid/data-model.mmd) |
| Nmap-Nuclei Pipeline | Detailed tool flow | [`mermaid/nmap-nuclei-pipeline.mmd`](mermaid/nmap-nuclei-pipeline.mmd) |
| Frontend Flow | API interactions | [`mermaid/frontend-flow.mmd`](mermaid/frontend-flow.mmd) |

To render Mermaid diagrams:
- Use a Mermaid-compatible Markdown viewer
- Paste into https://mermaid.live
- Use VS Code with Mermaid extension

## Recommended Reading Order

1. **[`architecture.md`](architecture.md)** — System components and communication
2. **[`scan-lifecycle.md`](scan-lifecycle.md)** — End-to-end scan flow
3. **[`data-model.md`](data-model.md)** — Entity relationships (`Scan`, `ScanTarget`, `Port`, `ToolExecution`, `Vulnerability`)
4. **[`tools-nmap-nuclei.md`](tools-nmap-nuclei.md)** — Nmap/Nuclei invocation, `NucleiProfile` mapping
5. **[`backend.md`](backend.md)** / **[`frontend.md`](frontend.md)** — Deeper component docs
6. **[`extending-scanners.md`](extending-scanners.md)** — Adding new tools
7. **[`performance.md`](performance.md)** — Tuning and scaling
8. **[`troubleshooting.md`](troubleshooting.md)** — Common issues

## Mental Model

```
┌─────────────────────────────────────────────────────────────────┐
│                           User                                  │
│                             │                                   │
│                             ▼                                   │
│                    ┌────────────────┐                           │
│                    │    Frontend    │  React + Vite             │
│                    │    (React)     │  Creates scans, shows     │
│                    └───────┬────────┘  results                  │
│                            │                                    │
│                            ▼                                    │
│                    ┌────────────────┐                           │
│                    │    Backend     │  FastAPI                  │
│                    │    (FastAPI)   │  REST API, auth,          │
│                    └───────┬────────┘  persistence              │
│                            │                                    │
│               ┌────────────┴────────────┐                       │
│               │                         │                       │
│               ▼                         ▼                       │
│      ┌────────────────┐        ┌────────────────┐               │
│      │     Worker     │        │    Database    │               │
│      │    (Celery)    │        │    (SQLite)    │               │
│      └───────┬────────┘        └────────────────┘               │
│              │                                                  │
│     ┌────────┼────────┬────────────┐                            │
│     │        │        │            │                            │
│     ▼        ▼        ▼            ▼                            │
│  ┌──────┐ ┌──────┐ ┌──────────┐ ┌─────────────────────┐         │
│  │ Nmap │ │Nuclei│ │ssh-audit │ │ NucleiProfile YAML  │         │
│  └──────┘ └──────┘ └──────────┘ │ (service mapping)   │         │
│                                 └─────────────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

## Common Commands

```bash
# Full rebuild
docker-compose down && docker-compose build && docker-compose up -d

# View logs
docker-compose logs -f celery
docker-compose logs -f backend
docker-compose logs -f frontend

# Restart single service
docker-compose restart celery

# Check service status
docker-compose ps

# Execute command in container
docker exec peek-celery-1 nuclei -version
docker exec peek-celery-1 nmap -version
```

## Getting Help

- **Documentation index**: [`README.md`](README.md)
- **Troubleshooting**: [`troubleshooting.md`](troubleshooting.md)
- **Contributing**: [`contributing.md`](contributing.md)

## Next Steps

Once you're comfortable with the basics:
1. Try modifying a `NucleiProfile` in `nuclei_profiles.yaml`
2. Add a new product tag and verify it's applied
3. Explore `backend/app/tasks/scan_tasks.py` to understand orchestration
4. Read [`extending-scanners.md`](extending-scanners.md) to add a new tool
