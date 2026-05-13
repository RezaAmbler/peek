# PEEK TODO

> **Port Enumeration & Evaluation Kit** - Development Roadmap

---

## 🔧 Scanner Enhancements

| Backlog | In Progress | Done |
|---------|-------------|------|
| Technology trend analysis across scans | - | httpx screenshot capture |
| WAF detection → adjusted scanning strategy | - | httpx vhost discovery |
| Batch mode for large scans | - | httpx HTTP prober integration |
| Plugin architecture for custom scanners | - | Nuclei vulnerability scanning |
| Asset tagging / device naming | - | ssh-audit integration |
| - | - | sslscan TLS analysis |
| - | - | NSE script integration |
| - | - | Nikto web server scanning |
| - | - | OWASP ZAP integration |
| - | - | Service-aware template selection |

---

## 📦 Open Source Release

| Backlog | In Progress | Done |
|---------|-------------|------|
| README with screenshots/GIFs | - | Security policy (SECURITY.md) |
| Demo video | - | Issue templates |
| - | - | Code of Conduct |
| - | - | Contributing guide (CONTRIBUTING.md) |
| - | - | API documentation |
| - | - | Architecture documentation |
| - | - | Troubleshooting guide |
| - | - | Usage guide |
| - | - | LICENSE file (MIT) |

---

## 🌐 Web UI

| Backlog | In Progress | Done |
|---------|-------------|------|
| Bulk actions (multi-select scans) | - | Dashboard with insights widgets |
| Export configuration profiles | - | Dark mode with user toggle |
| Import/export scan results | - | Target input on New Scan page |
| Keyboard shortcuts | - | Scan comparison/diff feature |
| - | - | Report generation (HTML, PDF, CSV) |
| - | - | Real-time scan progress |
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
| May 2026 | (Stage 18) | fix(comparisons): chronology auto-swap + run-picker label format + empty-state copy refinement (`38a2bdb`, `8a99f40`, `a926bdb`) |
| May 2026 | (Stage 17) | feat(frontend): confirm dialog on config edit + config_hash badge on scan detail + compare action label rename (`d86b190`, `bd78c04`, `33facef`) |
| May 2026 | (Stage 16) | feat(comparisons): require matching config_hash, not just config_id (`395821c`) |
| May 2026 | (Stage 14) | feat(scans): capture config snapshot and hash on scan creation (`be051df`) |
| May 2026 | (Stage 13) | feat(db): add config_snapshot and config_hash columns to scans (`62d6d6e`) |
| May 2026 | (Stage 11) | fix(frontend): compare-modal sources only comparable scans, surfaces mutation errors; hellbox scan #2 reuses scan #1 config (`e8b7f3d`, `e50955a`, `58c095b`) |
| May 2026 | (Stage 7) | feat(qa): end-to-end-qa orchestrator + hellbox-qa state inheritance + scripts/qa/README (`96ce38d`, `ec90a08`, `024d29a`) |
| May 2026 | (Stage 6) | feat(qa): peek-deploy.prompt for AI-orchestrated PEEK provisioning (`9619719`) |
| May 2026 | (Stage 5) | fix(deploy): parameterize deploy-prompt.txt + pre-flight deploy.sh (`0ae0fbe`, `3ef4886`) |
| May 2026 | (Stage 4) | chore(qa): consolidate hellbox QA into a single end-to-end prompt, remove superseded scripts (`0abbadd`, `84d3e8a`) |
| May 2026 | (Stage 3) | chore(tooling): pyproject + vitest + ESLint + Prettier + Makefile + .editorconfig |
| May 2026 | (Stage 2) | fix(deps): patch 5 CVE-affected packages (axios, requests, python-multipart, python-jose, jinja2); pin tool versions |
| May 2026 | (Stage 1) | docs/chore cleanup: pipeline docs, LICENSE, dead v1 stubs, secret-key hardening |
| Jan 2026 | `67160dc` | fix(security): comprehensive security hardening and bug fixes |
| Jan 2026 | `2e76f5b` | feat(httpx): add screenshot capture, vhost discovery, dynamic timeouts |
| Dec 2025 | `4b303a5` | feat(dashboard): add insights widgets and expanded stat cards |
| Dec 2025 | `46c762b` | feat(frontend): add dark mode support with user-controlled toggle |
| Dec 2025 | `1b56828` | feat(scans): Add target input to New Scan page |
| Dec 2025 | `16189a9` | feat: integrate httpx HTTP prober into scan pipeline |
| Dec 2025 | `9e3ea31` | feat: display config name as primary identifier in scans list |
| Dec 2025 | `fc24b63` | feat: comprehensive report generation improvements |
| Dec 2025 | `7a03ad3` | fix: resolve SQLite lock contention and config deletion errors |
| Dec 2025 | `8358a30` | feat: add git branch indicator to web UI footer |
| Dec 2025 | `e43f2c1` | feat: scan comparison/diff feature with enriched output |
| Dec 2025 | `ed3b9bb` | feat: Config-centric architecture — targets on config |
| Nov 2025 | `9135303` | fix: Resolve duplicate vulnerability bugs and stuck scan detection |
| Nov 2025 | `a76e712` | feat(ui): Add tool-specific sections and source badges |
| Nov 2025 | `a5962e5` | feat(scanner): Add Nikto and ZAP web scanning integration |
| Nov 2025 | `62a5127` | feat(scanner): Add NSE scripts and sslscan integration |
| Nov 2025 | `7507ec6` | Add Phase 4-5 developer docs |
| Nov 2025 | `c8c853c` | Add nuclei scanning enhancements: exclusions, tag validation |
| Nov 2025 | `e03d35c` | Add PEEK v2 full-stack implementation |

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
