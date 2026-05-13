# Contributing to PEEK

Thanks for your interest in contributing to PEEK! This document covers how to set up a development environment, the conventions we use for branches and commits, and what to include in a pull request.

## Code of Conduct

Participation in this project is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). By contributing you agree to abide by it.

## Reporting Security Issues

**Do not file public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for the private reporting process.

## Getting Started

### Prerequisites

- Python 3.9+ (backend, Celery worker)
- Node.js 18+ (frontend)
- Docker + Docker Compose (recommended for the full stack)
- Redis (Celery broker — handled for you by `docker-compose`)

### One-shot Local Setup

```bash
git clone https://github.com/RezaAmbler/peek.git
cd peek
make install        # creates .venv, installs backend + dev + frontend deps
```

### Running the Stack

The fastest path is `docker-compose up -d`, which brings up the frontend, backend, Celery worker, Celery beat, and Redis. See [README.md](README.md) for full instructions and the [docs/onboarding.md](docs/onboarding.md) developer guide for local-development details.

## Development Workflow

### Branching

Always work on a feature branch — never commit directly to `main`. Branch naming follows this pattern:

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feat/<scope>-<description>` | `feat/dashboard-insights-widgets` |
| Bug fix | `fix/<scope>-<description>` | `fix/vuln-query-join` |
| Docs | `docs/<description>` | `docs/api-stats-endpoint` |
| Refactor | `refactor/<scope>-<description>` | `refactor/scan-pipeline-async` |
| Chore | `chore/<description>` | `chore/update-dependencies` |

Common scopes: `dashboard`, `scans`, `configs`, `auth`, `celery`, `api`, `frontend`, `backend`, `comparisons`, `deploy`, `qa`.

### Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/). One-line summary, then an optional body.

```
<type>(<scope>): <imperative summary in lowercase>

<optional body explaining the why; wrap at ~72 chars>
```

Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `style`, `perf`, `build`, `ci`.

Examples:

```
feat(comparisons): require matching config_hash, not just config_id
fix(frontend): compare modal dropdown sources only comparable scans
docs(readme): correct API endpoint table and data model
chore(deps): bump axios to 1.16.0 to patch CVEs
```

### Tests

All changes must keep the test suite green:

```bash
make test                 # runs backend pytest + frontend vitest
make test-backend         # backend only
make test-frontend        # frontend only
```

The frontend production build and TypeScript type check must also pass:

```bash
cd frontend && npm run build
cd frontend && npx tsc --noEmit
```

When you add new behavior, add tests for it. When you fix a bug, add a regression test that fails before the fix and passes after.

### Linting & Formatting

```bash
make lint                 # frontend ESLint
make format               # frontend Prettier auto-format
make format-check         # check formatting without changes
```

Backend code follows PEP 8. The repo does not currently enforce a Python formatter; please match the surrounding style.

### Documentation

Update documentation alongside code changes:

- API surface changes → update [README.md](README.md) endpoint table and any affected `docs/` pages.
- Data model or schema changes → update [docs/data-model.md](docs/data-model.md) and the matching mermaid diagram in [docs/mermaid/](docs/mermaid/).
- New tools or scan phases → add a tool doc under [docs/tools/](docs/tools/) and update [docs/scan-lifecycle.md](docs/scan-lifecycle.md).
- Breaking changes → add a one-line changelog entry to [TODO.md](TODO.md).

## Pull Requests

1. **Open a PR against `main`.**
2. Title the PR with the same conventional-commit format as your commits.
3. Fill in the PR template (it autoloads from `.github/PULL_REQUEST_TEMPLATE.md`).
4. Link any related issues with `Closes #N`.
5. Make sure CI/local checks pass:
   - `make test`
   - `cd frontend && npm run build`
   - `cd frontend && npx tsc --noEmit`
6. Keep PRs scoped — prefer several small, reviewable PRs to one mega-PR.

## What We're Looking For

Good contributions:

- Small, focused changes with a clear motivation.
- Bug fixes that include a regression test.
- New scanner integrations following the pattern documented in [docs/extending-scanners.md](docs/extending-scanners.md).
- Documentation improvements — corrections, clarifications, or filling in gaps.
- Performance improvements with before/after measurements.

Things to avoid:

- Sweeping refactors without prior discussion (open an issue first).
- Adding heavy new dependencies without justification.
- Changes that bypass authentication, validation, or rate-limiting checks.
- Vendoring or modifying the integrated scanner tools (nmap, nuclei, etc.) — those upstreams are the right place for tool fixes.

## Questions?

- Open a [GitHub Discussion](https://github.com/RezaAmbler/peek/discussions) for design questions or general chat.
- Open a [GitHub Issue](https://github.com/RezaAmbler/peek/issues) for bug reports or specific feature proposals.
- Email reza.ambler@gmail.com for anything else.
