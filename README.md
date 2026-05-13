```
 ____  _____ _____ _  __ __     ______
|  _ \| ____| ____| |/ / \ \   / /___ \
| |_) |  _| |  _| | ' /   \ \ / /  __) |
|  __/| |___| |___| . \    \ V /  / __/
|_|   |_____|_____|_|\_\    \_/  |_____|

Port Enumeration & Evaluation Kit
```

<div align="center">

[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Tools](https://img.shields.io/badge/Security-11%20Tools-red)](https://github.com)

**Modern network security scanner with historical comparison capabilities**

[Features](#-features) • [Quick Start](#-quick-start) • [Architecture](#-architecture) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## 🎯 Overview

**PEEK V2** is a comprehensive network security scanning platform that combines multiple industry-standard security tools into a unified, user-friendly interface. Built for security professionals, network engineers, and DevOps teams, PEEK automates vulnerability discovery, service enumeration, and compliance auditing while tracking changes over time.

### Why PEEK?

- **Unified Platform**: Orchestrates 11 security tools through a single interface
- **Historical Tracking**: Compare scans over time to identify new vulnerabilities and configuration changes
- **Service-Aware Scanning**: Automatically selects appropriate vulnerability checks based on detected services
- **Flexible Scheduling**: Configure recurring scans with cron-based scheduling
- **Rich Reporting**: Export findings in PDF, HTML, and CSV formats
- **Modern UI**: Dark mode support, real-time progress tracking, and intuitive dashboards

---

## ✨ Features

### 🔍 Comprehensive Security Scanning

| Tool | Purpose | Capabilities |
|------|---------|--------------|
| **Nmap** | Port & Service Discovery | Top-ports discovery, service versioning, NSE scripting |
| **httpx** | HTTP Probing | Tech detection, screenshots, TLS probing, vhost discovery |
| **Katana** | Endpoint Discovery | Web crawling, form detection, API path discovery |
| **ssh-audit** | SSH Hardening Analysis | Algorithm assessment, CVE detection, compliance scoring |
| **Nuclei** | Vulnerability Detection | 5000+ templates with service-aware filtering |
| **Nmap NSE** | Service Scripts | Targeted scripts for RDP, SMB, SMTP, DNS, FTP, NTP |
| **sslscan** | Quick TLS Assessment | Protocol support, cipher strength, certificate validation |
| **testssl.sh** | Deep TLS Analysis | Heartbleed, POODLE, BEAST, DROWN, ROBOT checks |
| **Nikto** | Web Server Scanning | Misconfiguration detection, known vulnerability checks |
| **OWASP ZAP** | Web App Testing | Baseline security scans, automated spidering |
| **masscan** | Fast Port Scanning | Legacy (replaced by Nmap discovery in v2.2.0) |

### 📊 Scan Pipeline (12 Phases)

```
1. Port Discovery (0-10%)        → Identifies open ports
2. Service Detection (10-75%)    → Determines service versions
3. HTTP Probing (75-78%)         → httpx tech detection & screenshots
3.5. Endpoint Discovery (78-80%) → Katana web crawling
4. SSH Audit (80-85%)            → Analyzes SSH security
5. Nuclei Per-Port (85-88%)      → Vulnerability scanning per port
5.5. Nuclei Endpoints (88-91%)   → Scans discovered endpoints
6. NSE Scripts (91-93%)          → Nmap scripting engine
7. SSLScan (93-95%)              → Quick TLS/SSL analysis
7.5. testssl.sh (95-97%)         → Deep TLS vulnerability checks
8. Nikto (97-98%)                → Web server security tests
9. ZAP (98-100%)                 → OWASP ZAP baseline scan
```

### 🎨 Modern Features

- **Smart Dashboard**: Real-time statistics, recent scans, vulnerability summaries
- **Dark Mode**: User-controlled theme with persistent preferences
- **Historical Comparison**: Diff engine showing new/closed ports and vulnerability changes
- **Scan Configurations**: Reusable profiles with tool toggles, timeouts, and severity filters
- **Scheduled Scans**: Cron-based recurring scans with automatic execution
- **Report Generation**: Professional reports with charts, tables, and executive summaries
- **RESTful API**: Full OpenAPI/Swagger documentation at `/docs`

---

## 🚀 Quick Start

### Prerequisites

- Docker 20.10+ and Docker Compose 2.0+
- 4GB RAM minimum (8GB recommended)
- 10GB disk space for tool images and scan data

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/RezaAmbler/peek.git
   cd peek
   ```

2. **Configure environment**
   ```bash
   cp backend/.env.example backend/.env
   # Edit backend/.env and set SECRET_KEY
   openssl rand -hex 32  # Use this output as SECRET_KEY
   ```

3. **Start all services**
   ```bash
   docker compose up -d
   ```

4. **Access the application**
   - **Frontend UI**: http://localhost:3000
   - **API Documentation**: http://localhost:8000/docs
   - **Backend Health**: http://localhost:8000/api/health

5. **Login with default credentials**
   - Username: `admin`
   - Password: `admin`
   - **⚠️ Change immediately in production!**

### First Scan

1. Navigate to **New Scan** in the UI
2. Enter target (IP, hostname, or CIDR range)
3. Select scan configuration or use defaults
4. Click **Start Scan** and monitor progress
5. View results in **Ports** and **Vulnerabilities** tabs

---

## 🏗 Architecture

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   React     │────▶ │   FastAPI   │────▶ │   Celery    │
│  Frontend   │      │   Backend   │      │   Worker    │
│  (Port 3000)│      │  (Port 8000)│      │             │
└─────────────┘      └─────────────┘      └─────────────┘
       │                    │                     │
       │                    │                     ▼
       │                    │              ┌─────────────┐
       │                    │              │   Security  │
       │                    │              │    Tools    │
       │                    │              │  (11 tools) │
       │                    │              └─────────────┘
       │                    ▼                     │
       │             ┌─────────────┐             │
       └────────────▶│   SQLite    │◀────────────┘
                     │  Database   │
                     │  (WAL mode) │
                     └─────────────┘
                            ▲
                            │
                     ┌─────────────┐
                     │ Celery Beat │
                     │  Scheduler  │
                     └─────────────┘
```

### Technology Stack

#### Backend
- **Framework**: FastAPI 0.109 with OpenAPI/Swagger
- **ORM**: SQLAlchemy 2.0 (async)
- **Database**: SQLite with WAL mode (async via aiosqlite)
- **Task Queue**: Celery 5.3 + Redis 7
- **Validation**: Pydantic 2.5
- **Auth**: JWT tokens (python-jose, bcrypt) - 7-day expiration

#### Frontend
- **Framework**: React 18 with TypeScript 5.3
- **Build Tool**: Vite 5
- **Routing**: TanStack Router
- **Data Fetching**: TanStack Query (React Query)
- **State Management**: Zustand
- **Styling**: Tailwind CSS 3.4
- **UI Components**: Custom component library with dark mode

#### Infrastructure
- **Containerization**: Docker with multi-stage builds
- **Orchestration**: Docker Compose
- **Message Broker**: Redis 7
- **Reverse Proxy**: Nginx (production)

### Data Model

```
ScanConfig (Reusable scan profile)
  ├── targets: [IP, hostname, CIDR]
  ├── tool_settings: JSON configuration
  └── schedule: Cron expression
       │
       ├─▶ Scan (Execution instance)
       │    ├── run_number: Auto-increment per config
       │    ├── status: pending/running/completed/failed
       │    ├── progress: 0-100%
       │    ├── config_snapshot: JSON capture of the config at scan time
       │    └── config_hash: SHA-256 of comparable config fields
       │         │
       │         ├─▶ ScanTarget (Per-target results)
       │         │    └─▶ Port (Discovered services)
       │         │         ├── service, version, product
       │         │         └─▶ Vulnerability
       │         │              ├── severity, CVE, description
       │         │              └── tool: nuclei/nikto/zap/nse
       │         │
       │         ├─▶ HttpxResult (HTTP probing)
       │         ├─▶ DiscoveredEndpoint (Katana crawling)
       │         ├─▶ SSHAudit (SSH analysis)
       │         ├─▶ SslScanResult (sslscan)
       │         ├─▶ TestsslResult (testssl.sh)
       │         ├─▶ NseFinding (NSE script output)
       │         └─▶ ToolExecution (Raw output)
       │
       └─▶ ScanComparison (Baseline diff)
            ├── new_ports, closed_ports
            └── new_vulns, resolved_vulns
```

> Scans capture the full scan configuration at execution time (`config_snapshot`) and a SHA-256 hash of the comparable fields (`config_hash`). Two scans are only comparable when their config hashes match — editing a configuration creates a new hash that breaks comparability with prior scans on that configuration.

---

## 📦 Docker Services

| Service | Port | Purpose | Auto-Start |
|---------|------|---------|------------|
| `frontend` | 3000 | React UI (Nginx in prod) | Yes |
| `backend` | 8000 | FastAPI + Swagger docs | Yes |
| `celery` | - | Scan execution worker | Yes |
| `celery-beat` | - | Scheduled scan scheduler | Yes |
| `redis` | 6379 | Celery message broker | Yes |
| `zap` | 8090 | OWASP ZAP daemon (optional) | No |

### Docker Commands

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f celery        # Worker logs
docker compose logs -f backend       # API logs
docker compose logs -f frontend      # Nginx logs

# Rebuild after code changes
docker compose up -d --build backend celery celery-beat

# Stop all services
docker compose down

# Stop and remove volumes (DELETES DATABASE)
docker compose down -v
```

---

## 🔧 Development Setup

### Backend Development

```bash
# One-shot setup (from repo root):
make install            # Creates .venv, installs backend + dev + frontend deps
source .venv/bin/activate

# Set environment variables (or set in backend/.env)
export DATABASE_URL="sqlite+aiosqlite:///./peek.db"
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

# Run development server
uvicorn app.main:app --reload --port 8000 --app-dir backend

# In separate terminal: Start Celery worker
cd backend && celery -A app.celery_app worker --loglevel=info

# In another terminal: Start Celery beat scheduler
cd backend && celery -A app.celery_app beat --loglevel=info
```

### Frontend Development

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview

# Type checking
npm run typecheck

# Linting
npm run lint
npm run lint:fix
```

### Running Tests

```bash
# All tests (from repo root)
make test

# Backend only (pytest from repo root, uses pyproject.toml)
make test-backend           # or: pytest
pytest -v                   # verbose

# Frontend only (vitest)
make test-frontend          # or: cd frontend && npm test
cd frontend && npm run test:coverage
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Usage Guide](docs/usage-guide.md) | Step-by-step user manual |
| [Architecture](docs/architecture.md) | System design and components |
| [API Documentation](http://localhost:8000/docs) | Interactive Swagger/OpenAPI docs |
| [Scan Lifecycle](docs/scan-lifecycle.md) | Detailed 12-phase scan breakdown |
| [Tool Documentation](docs/tools/README.md) | Individual tool guides (11 tools) |
| [Data Model](docs/data-model.md) | Database schema and relationships |
| [Backend](docs/backend.md) | Tool wrappers, parsers, services |
| [Frontend](docs/frontend.md) | React components and state management |
| [Extending Scanners](docs/extending-scanners.md) | Adding new security tools |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and solutions |
| [Performance](docs/performance.md) | Optimization and tuning guide |

---

## 🔐 Security Considerations

### Default Credentials
The default `admin/admin` credentials are **ONLY** for development. For production:

1. Change admin password immediately after first login
2. Create individual user accounts for each team member
3. Disable the default admin account after creating alternatives

### JWT Token Security
- Tokens expire after 7 days
- Store tokens securely (localStorage with HttpOnly consideration for production)
- Rotate the `SECRET_KEY` regularly in production environments

### Network Scanning Ethics
- **Only scan networks you own or have explicit permission to test**
- Unauthorized scanning may violate computer fraud laws
- Configure appropriate timeouts to avoid DoS conditions
- Review and comply with your organization's security policies

### Tool Safety
All integrated tools are:
- Open source with active communities
- Industry-standard security testing tools
- Regularly updated in Docker images
- Isolated in containers for safety

---

## 🛠 Configuration

### Scan Configuration Options

Configure scanning behavior via the UI or API:

```json
{
  "name": "Production Infrastructure",
  "targets": ["192.168.1.0/24", "webserver.example.com"],
  "nmap_enabled": true,
  "nmap_top_ports": 1000,
  "nmap_timing": "T3",
  "nuclei_enabled": true,
  "nuclei_severity": ["critical", "high", "medium", "low"],
  "ssh_audit_enabled": true,
  "sslscan_enabled": true,
  "nikto_enabled": false,
  "zap_enabled": false,
  "scan_timeout": 3600,
  "schedule": "0 2 * * 0"  // Weekly at 2 AM Sunday
}
```

### Environment Variables

Create `backend/.env` from template:

```bash
# Security
SECRET_KEY=your-secret-key-generated-with-openssl
ACCESS_TOKEN_EXPIRE_DAYS=7

# Database
DATABASE_URL=sqlite+aiosqlite:///./data/peek.db

# Celery
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/0

# External Tools
ZAP_API_KEY=your-zap-api-key
ZAP_PROXY_URL=http://zap:8090

# Application
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
LOG_LEVEL=INFO
```

---

## 🌐 API Reference

### Key Endpoints

Full interactive docs are served at `/docs` by FastAPI. The table below is a curated subset; the complete surface is generated from the routers under `backend/app/routers/`.

**Auth**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | Authenticate (form-encoded `username` + `password`) → JWT |
| `GET`  | `/api/auth/me`    | Current user info |

**Configs**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`    | `/api/configs`                       | List scan configurations |
| `POST`   | `/api/configs`                       | Create configuration |
| `GET`    | `/api/configs/{id}`                  | Get one |
| `PATCH`  | `/api/configs/{id}`                  | Update |
| `DELETE` | `/api/configs/{id}`                  | Delete |
| `POST`   | `/api/configs/{id}/set-default`      | Mark as default |

**Scans**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`    | `/api/scans`                                   | List scans |
| `POST`   | `/api/scans`                                   | Create scan (body: `{ "config_id": "<uuid>" }`) |
| `GET`    | `/api/scans/{id}`                              | Scan detail |
| `PATCH`  | `/api/scans/{id}`                              | Update scan metadata |
| `DELETE` | `/api/scans/{id}`                              | Delete scan |
| `POST`   | `/api/scans/{id}/start`                        | Queue scan for execution |
| `POST`   | `/api/scans/{id}/cancel`                       | Cancel running scan |
| `POST`   | `/api/scans/{id}/restart`                      | Restart as a new run of the same config |
| `GET`    | `/api/scans/{id}/comparable`                   | Scans comparable to this one (same `config_hash`) |
| `GET`    | `/api/scans/{id}/ports`                        | Discovered ports |
| `GET`    | `/api/scans/{id}/vulnerabilities`              | Findings |
| `GET`    | `/api/scans/{id}/httpx-results`                | httpx results |
| `GET`    | `/api/scans/{id}/discovered-endpoints`         | Katana endpoints |
| `GET`    | `/api/scans/{id}/ssh-audits`                   | ssh-audit results |
| `GET`    | `/api/scans/{id}/sslscan-results`              | sslscan results |
| `GET`    | `/api/scans/{id}/testssl-results`              | testssl.sh results |
| `GET`    | `/api/scans/{id}/nse-findings`                 | NSE script findings |
| `GET`    | `/api/scans/{id}/screenshots/{port_id}`        | httpx screenshot for a port |

**Comparisons**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/comparisons/compare`         | Compare two scans (validates same `config_hash`) |
| `GET`  | `/api/comparisons/{id}`            | Get a saved comparison |
| `GET`  | `/api/comparisons/scan/{scan_id}`  | List comparisons involving a scan |

**Scheduled scans**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`    | `/api/scheduled-scans`                  | List schedules |
| `POST`   | `/api/scheduled-scans`                  | Create |
| `PATCH`  | `/api/scheduled-scans/{id}`             | Update |
| `DELETE` | `/api/scheduled-scans/{id}`             | Delete |
| `POST`   | `/api/scheduled-scans/{id}/pause`       | Pause |
| `POST`   | `/api/scheduled-scans/{id}/resume`      | Resume |
| `POST`   | `/api/scheduled-scans/{id}/run-now`     | Trigger immediately |

**Reports**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/reports/{scan_id}/pdf/executive`          | Executive summary PDF |
| `GET` | `/api/reports/{scan_id}/pdf/technical`          | Technical PDF |
| `GET` | `/api/reports/{scan_id}/html`                   | HTML report |
| `GET` | `/api/reports/{scan_id}/csv/vulnerabilities`    | Vulnerabilities CSV |
| `GET` | `/api/reports/{scan_id}/csv/ports`              | Ports CSV |
| `GET` | `/api/reports/{scan_id}/csv/summary`            | Summary CSV |
| `GET` | `/api/reports/comparison/{comparison_id}/pdf`   | Comparison PDF |

**Stats**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/stats` | Dashboard statistics |

### Full API Documentation

Interactive Swagger UI available at: **http://localhost:8000/docs**

Example: log in, pick a config, create a scan, queue it.

```bash
# 1) Authenticate (form-encoded body) and capture the JWT
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin" \
  | jq -r '.access_token')

# 2) Grab a config id (UUID string)
CONFIG_ID=$(curl -s http://localhost:8000/api/configs \
  -H "Authorization: Bearer $TOKEN" | jq -r '.items[0].id')

# 3) Create a scan against that config
SCAN_ID=$(curl -s -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"config_id\": \"$CONFIG_ID\"}" | jq -r '.id')

# 4) Queue the scan for execution
curl -s -X POST "http://localhost:8000/api/scans/$SCAN_ID/start" \
  -H "Authorization: Bearer $TOKEN"
```

---

## 🤝 Contributing

We welcome contributions! PEEK is open source and thrives on community involvement.

### How to Contribute

1. **Fork the repository**
   ```bash
   git clone https://github.com/RezaAmbler/peek.git
   cd peek
   git checkout -b feature/your-feature-name
   ```

2. **Set up development environment**
   ```bash
   # Follow Development Setup instructions above
   docker compose up -d
   ```

3. **Make your changes**
   - Follow existing code style
   - Add tests for new features
   - Update documentation as needed

4. **Test your changes**
   ```bash
   # All tests + lint + format check (from repo root)
   make test               # backend pytest + frontend vitest
   make lint               # frontend ESLint
   make format-check       # frontend Prettier check
   ```

5. **Submit a pull request**
   - Write clear commit messages
   - Reference related issues
   - Include screenshots for UI changes

### Development Guidelines

- **Code Style**: Follow PEP 8 (Python) and ESLint config (TypeScript)
- **Testing**: Maintain 80%+ test coverage
- **Documentation**: Update docs for API/feature changes
- **Commits**: Use conventional commits (feat:, fix:, docs:, etc.)

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 📋 Roadmap

### Upcoming Features

- [ ] **Advanced Reporting**: Custom report templates with Jinja2
- [ ] **Plugin System**: Custom scanner integration framework
- [ ] **Alert Integration**: Slack, email, webhook notifications
- [ ] **Compliance Scanning**: CIS benchmarks, NIST framework mappings
- [ ] **Export Formats**: JSON, XML, Markdown report options
- [ ] **Asset Management**: Track hosts, services, and infrastructure
- [ ] **Credential Scanning**: Authenticated vulnerability checks
- [ ] **Network Mapping**: Automatic topology discovery
- [ ] **API Rate Limiting**: Prevent abuse with token buckets

### Integration Plans

- Jira/ServiceNow ticketing for vulnerability tracking
- SIEM export (Splunk, ELK, QRadar)
- CI/CD pipeline integration (Jenkins, GitLab CI)
- Cloud provider scanning (AWS, Azure, GCP)

See [TODO.md](TODO.md) for complete task list.

---

## 🐛 Troubleshooting

### Common Issues

**Celery worker not processing scans**
```bash
# Check worker is running
docker compose ps celery

# View worker logs
docker compose logs -f celery

# Restart worker
docker compose restart celery
```

**Database locked errors**
```bash
# SQLite WAL mode should prevent this, but if it occurs:
docker compose down
docker compose up -d
```

**Port conflicts**
```bash
# Check what's using port 8000
lsof -i :8000

# Change ports in docker-compose.yml if needed
```

**Tools not found in worker**
```bash
# Rebuild worker container to get latest tool versions
docker compose build celery
docker compose up -d celery
```

See [Troubleshooting Guide](docs/troubleshooting.md) for more solutions.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024-2026 Reza Ambler and contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Acknowledgments

PEEK integrates and builds upon these excellent open-source projects:

- [Nmap](https://nmap.org/) - Network exploration and security auditing
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Fast vulnerability scanner
- [httpx](https://github.com/projectdiscovery/httpx) - HTTP toolkit
- [Katana](https://github.com/projectdiscovery/katana) - Web crawler
- [ssh-audit](https://github.com/jtesta/ssh-audit) - SSH server auditing
- [sslscan](https://github.com/rbsec/sslscan) - SSL/TLS scanner
- [testssl.sh](https://github.com/drwetter/testssl.sh) - Deep TLS analysis
- [Nikto](https://cirt.net/Nikto2) - Web server scanner
- [OWASP ZAP](https://www.zaproxy.org/) - Web application security scanner
- [masscan](https://github.com/robertdavidgraham/masscan) - Fast port scanner (legacy)

Built with:
- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [React](https://reactjs.org/) - UI library
- [TanStack](https://tanstack.com/) - Powerful React tools
- [Tailwind CSS](https://tailwindcss.com/) - Utility-first CSS

### Contributors

- [Brandon Seaver](https://github.com/brndnsvr) — contributor

---

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/RezaAmbler/peek/issues)
- **Discussions**: [GitHub Discussions](https://github.com/RezaAmbler/peek/discussions)
- **Security**: See [SECURITY.md](SECURITY.md), or report vulnerabilities privately to reza.ambler@gmail.com

---

<div align="center">

**Made with ❤️ by security professionals, for security professionals**

[⬆ Back to Top](#peek-v2---port-enumeration--evaluation-kit)

</div>
