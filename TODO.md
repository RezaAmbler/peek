# PEEK TODO

> **Port Enumeration & Evaluation Kit** - Development Roadmap

---

## ☁️ SaaS Infrastructure

| Backlog | In Progress | Done |
|---------|-------------|------|
| PostgreSQL migration | - | - |
| Multi-tenant architecture | - | - |
| Stripe billing integration | - | - |
| Self-service onboarding flow | - | - |
| Rate limiting | - | - |
| Audit logging | - | - |
| HTTPS auto-configuration | - | - |
| Email infrastructure (notifications) | - | - |

---

## 🔧 Scanner Enhancements

| Backlog | In Progress | Done |
|---------|-------------|------|
| httpx screenshot capture | - | httpx HTTP prober integration |
| httpx vhost discovery | - | Nuclei vulnerability scanning |
| Technology trend analysis across scans | - | ssh-audit integration |
| WAF detection → adjusted scanning strategy | - | sslscan TLS analysis |
| Batch mode for large scans | - | NSE script integration |
| Plugin architecture for custom scanners | - | Nikto web server scanning |
| Masscan fast discovery mode | - | OWASP ZAP integration |
| Asset tagging / device naming | - | Service-aware template selection |

---

## 📦 Open Source Release

| Backlog | In Progress | Done |
|---------|-------------|------|
| README with screenshots/GIFs | - | CLAUDE.md development guide |
| LICENSE file (MIT) | - | API documentation |
| CONTRIBUTING.md | - | Architecture documentation |
| GitHub Actions CI | - | Troubleshooting guide |
| Demo video | - | Usage guide |
| Security policy (SECURITY.md) | - | - |
| Issue templates | - | - |

---

## 🌐 Web UI

| Backlog | In Progress | Done |
|---------|-------------|------|
| Dashboard with scan overview | - | Dark mode with user toggle |
| Bulk actions (multi-select scans) | - | Target input on New Scan page |
| Export configuration profiles | - | Scan comparison/diff feature |
| Import/export scan results | - | Report generation (HTML, PDF, CSV) |
| Keyboard shortcuts | - | Real-time scan progress |
| - | - | Git branch indicator in footer |
| - | - | Config-centric architecture |

---

## 🛠️ Infrastructure & DevOps

| Backlog | In Progress | Done |
|---------|-------------|------|
| Kubernetes Helm chart | - | Docker Compose deployment |
| Terraform modules | - | Production deployment scripts |
| Health check endpoints for k8s | - | SQLite WAL mode + lock fixes |
| Prometheus metrics export | - | Celery worker configuration |
| Grafana dashboard templates | - | Redis broker setup |

---

## Changelog

Recent completed work (newest first):

| Date | Commit | Description |
|------|--------|-------------|
| Dec 2024 | `46c762b` | feat(frontend): add dark mode support with user-controlled toggle |
| Dec 2024 | `1b56828` | feat(scans): Add target input to New Scan page |
| Dec 2024 | `16189a9` | feat: integrate httpx HTTP prober into scan pipeline |
| Dec 2024 | `9e3ea31` | feat: display config name as primary identifier in scans list |
| Dec 2024 | `fc24b63` | feat: comprehensive report generation improvements |
| Dec 2024 | `7a03ad3` | fix: resolve SQLite lock contention and config deletion errors |
| Dec 2024 | `8358a30` | feat: add git branch indicator to web UI footer |
| Dec 2024 | `e43f2c1` | feat: scan comparison/diff feature with enriched output |
| Dec 2024 | `ed3b9bb` | feat: Config-centric architecture — targets on config |
| Dec 2024 | `9135303` | fix: Resolve duplicate vulnerability bugs and stuck scan detection |
| Dec 2024 | `a76e712` | feat(ui): Add tool-specific sections and source badges |
| Dec 2024 | `a5962e5` | feat(scanner): Add Nikto and ZAP web scanning integration |
| Dec 2024 | `62a5127` | feat(scanner): Add NSE scripts and sslscan integration |
| Dec 2024 | `7507ec6` | Add Phase 4-5 developer docs |
| Dec 2024 | `c8c853c` | Add nuclei scanning enhancements: exclusions, tag validation |
| Dec 2024 | `e03d35c` | Add PEEK v2 full-stack implementation |

---

## How to Use This Board

**Moving items:**
1. Cut the item text from one column
2. Paste into the new column
3. Replace `-` placeholder if needed

**Adding items:**
- Add new row to the appropriate table
- Use `|` separators between columns

**Conventions:**
- One item per cell
- Use `-` for empty cells
- Keep descriptions concise (< 40 chars)
