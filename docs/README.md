# PEEK Documentation

After reading this doc set you'll understand:
- What PEEK does and the main pieces involved (Frontend, Backend API, Worker, external tools).
- How a scan runs end-to-end (Nmap discovery → NucleiProfile mapping → Nuclei per port → stored findings).
- Where to look for architecture, lifecycle, data, and extension details.
- How severity (including LOW/INFO) is handled and surfaced in the UI.
- How comparisons work and why two scans are or aren't comparable.

## How to Use These Docs

Start with [`onboarding.md`](onboarding.md) for a guided introduction, then explore by topic:

| Topic | Document | Diagram |
|-------|----------|---------|
| System overview | [`architecture.md`](architecture.md) | [`mermaid/system-overview.mmd`](mermaid/system-overview.mmd) |
| Scan flow | [`scan-lifecycle.md`](scan-lifecycle.md) | [`mermaid/scan-lifecycle.mmd`](mermaid/scan-lifecycle.mmd) |
| Data model | [`data-model.md`](data-model.md) | [`mermaid/data-model.mmd`](mermaid/data-model.mmd) |
| Backend internals | [`backend.md`](backend.md), [`tools/`](tools/) | [`mermaid/scan-pipeline.mmd`](mermaid/scan-pipeline.mmd) |
| Frontend overview | [`frontend.md`](frontend.md) | [`mermaid/frontend-flow.mmd`](mermaid/frontend-flow.mmd) |
| Usage & troubleshooting | [`usage-guide.md`](usage-guide.md), [`troubleshooting.md`](troubleshooting.md) | — |
| Codebase overview | [`codebase-tour.md`](codebase-tour.md) | — |
| Extending scanners | [`extending-scanners.md`](extending-scanners.md) | — |
| Performance/scaling | [`performance.md`](performance.md) | — |
| Developer onboarding | [`onboarding.md`](onboarding.md) | [`mermaid/system-overview.mmd`](mermaid/system-overview.mmd) |
| Contributing | [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | — |

## What is PEEK?

PEEK is a network scanner and reporting platform that orchestrates Nmap for discovery and service detection, maps detected services to NucleiProfile configurations, runs Nuclei per port, and stores parsed vulnerabilities so the UI can show complete findings (including LOW/INFO when enabled).

## Quick Start (First Day Checklist)

1. Run the dev stack (API, Frontend, Worker, DB).
2. Trigger a test scan from the Frontend or API.
3. Open the scan detail page to see `ScanTarget`s, `Port`s, and `Vulnerability` records.
4. Ensure `nuclei_severity` includes `low,info` so the UI tables show informational/low findings.

For detailed setup instructions, see [`onboarding.md`](onboarding.md).

## Document Index

### Core Documentation
- **Architecture**: [`architecture.md`](architecture.md) — High-level system components and communication
- **Scan Lifecycle**: [`scan-lifecycle.md`](scan-lifecycle.md) — Step-by-step 12-phase scan flow
- **Data Model**: [`data-model.md`](data-model.md) — Entities, `config_snapshot`/`config_hash`, comparability rules

### Deep Dives
- **Backend**: [`backend.md`](backend.md) — Celery tasks, tool wrappers, parsers, service profiles
- **Tool docs**: [`tools/`](tools/) — One file per integrated tool (Nmap, httpx, Katana, Nuclei, …)
- **Frontend**: [`frontend.md`](frontend.md) — React pages, API clients, compare-modal flow

### Operations
- **Usage Guide**: [`usage-guide.md`](usage-guide.md) — Running fast/deep scans, comparing scans, interpreting results
- **Troubleshooting**: [`troubleshooting.md`](troubleshooting.md) — Common issues and diagnostics
- **Performance**: [`performance.md`](performance.md) — Tuning Nmap, Nuclei, Celery, database

### Development
- **Codebase Tour**: [`codebase-tour.md`](codebase-tour.md) — Directory layout and where logic lives
- **Extending Scanners**: [`extending-scanners.md`](extending-scanners.md) — Adding new tools and NucleiProfile mappings
- **Developer Onboarding**: [`onboarding.md`](onboarding.md) — Setup, first-day tasks, recommended reading
- **Contributing**: [`../CONTRIBUTING.md`](../CONTRIBUTING.md) — Branching, commits, PR requirements

### Diagrams (Mermaid)
- [`mermaid/system-overview.mmd`](mermaid/system-overview.mmd) — Top-level system diagram
- [`mermaid/overview.mmd`](mermaid/overview.mmd) — Component overview
- [`mermaid/scan-lifecycle.mmd`](mermaid/scan-lifecycle.mmd) — Scan flow phases
- [`mermaid/data-model.mmd`](mermaid/data-model.mmd) — Entity relationships (incl. config_snapshot / config_hash)
- [`mermaid/scan-pipeline.mmd`](mermaid/scan-pipeline.mmd) — Complete 12-phase scan pipeline
- [`mermaid/frontend-flow.mmd`](mermaid/frontend-flow.mmd) — Frontend API interactions
