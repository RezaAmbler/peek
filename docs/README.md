# PEEK Documentation

After reading this doc set you’ll understand:
- What PEEK does and the main pieces involved (frontend, backend API, worker, external tools).
- How a scan runs end-to-end (Nmap discovery → service profiles → nuclei per port → stored findings).
- Where to look for architecture, lifecycle, data, and extension details.
- How severity (including low/info) is handled and surfaced in the UI.

## How to use these docs
- `architecture.md`: High-level system components and how they talk.
- `scan-lifecycle.md`: Step-by-step of a scan from user action to UI results, with links to nuclei/Nmap details.
- `mermaid/overview.mmd` and `mermaid/scan-lifecycle.mmd`: Diagram sources you can render for quick visuals.
- Future phases will add deeper backend, data-model, frontend, operations, and extending guides.

## What is PEEK?
PEEK is a network scanner and reporting platform that orchestrates Nmap for discovery and service detection, maps detected services to Nuclei profiles, runs nuclei per port, and stores parsed vulnerabilities so the UI can show complete findings (including low/info when enabled).

## First day as a developer (checklist)
- Run the dev stack (API, frontend, worker, DB).
- Trigger a test scan from the frontend or API.
- Open the scan detail page to see targets, ports, and vulnerabilities.
- Ensure `nuclei_severity` includes `info,low` so the UI tables show informational/low findings.

## Doc index (Phase 1)
- Overview architecture: `architecture.md` (diagram: `mermaid/overview.mmd`)
- Scan flow: `scan-lifecycle.md` (diagram: `mermaid/scan-lifecycle.mmd`)
- Data model: `data-model.md` (diagram: `mermaid/data-model.mmd`)
- Backend internals: `backend.md`, `tools-nmap-nuclei.md`
- Frontend overview: `frontend.md`
- Usage & troubleshooting: `usage-guide.md`, `troubleshooting.md`
- Codebase overview: `codebase-tour.md`
- Extending scanners: `extending-scanners.md`
- Performance/scaling: `performance.md`
- Detailed pipelines: `mermaid/nmap-nuclei-pipeline.mmd`, `mermaid/frontend-flow.mmd`
