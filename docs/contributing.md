# Contributing to PEEK

This guide covers contribution standards for the PEEK project.

## Branching Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Production-ready code |
| `dev` | Integration branch for features |
| `feature/<name>` | New features |
| `fix/<name>` | Bug fixes |
| `docs/<name>` | Documentation updates |

**Workflow**:
1. Create feature branch from `dev`
2. Develop and test locally
3. Open PR to `dev`
4. After review, merge to `dev`
5. Periodically merge `dev` to `main` for releases

## Commit Conventions

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Formatting, no code change |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf` | Performance improvement |
| `test` | Adding missing tests |
| `chore` | Build process or auxiliary tool changes |

### Examples

```bash
feat(nuclei): add support for custom rate limits per profile
fix(nmap): handle timeout on service detection phase
docs(scan-lifecycle): add diagram for NucleiProfile mapping
refactor(tasks): extract nuclei phase into separate function
```

## Linting & Static Analysis

### Backend (Python)

```bash
# Run linting
cd backend
ruff check .

# Run type checking
mypy app/

# Format code
black app/
```

### Frontend (TypeScript)

```bash
# Run linting
cd frontend
npm run lint

# Type checking
npm run typecheck

# Format code
npm run format
```

## Expectations for Scanning Changes

### When to Update `nuclei_profiles.yaml`

- Adding support for a new service type
- Adding product-specific tags for better template matching
- Adjusting rate limits or timeout multipliers
- Modifying scan mode behavior (`fast`/`deep`)
- Adding template exclusions

### How to Add New `NucleiProfile`s

1. Check if Nuclei has templates for the service:
   ```bash
   docker exec peek-celery-1 nuclei -tl -tags <service_name>
   ```

2. Add entry to `backend/config/nuclei_profiles.yaml`:
   ```yaml
   service_profiles:
     new_service:
       target_format: host_port  # or 'url'
       protocol: null            # or 'http', 'https'
       tags: [new_service, network]
       timeout_multiplier: 0.5
       rate_limit: 50  # Optional
   ```

3. If product-specific, add to `product_tags`:
   ```yaml
   product_tags:
     product_name: [product_tag]
   ```

4. Test with a scan targeting that service type

### How to Add New Scanners

See [`extending-scanners.md`](extending-scanners.md) for detailed guidance:

1. Create wrapper in `backend/app/tools/<tool>.py`
2. Create parser in `backend/app/parsers/<tool>_parser.py`
3. Add phase in `backend/app/tasks/scan_tasks.py`
4. Create `ToolExecution` records with proper linkage
5. Update documentation

### When to Update Diagrams

Update diagrams in `docs/mermaid/` when:
- Adding a new scan phase
- Changing the data flow between components
- Adding new entity relationships
- Modifying the Frontend-Backend-Worker interaction

## Documentation Requirements for PRs

### Required Documentation Updates

| Change Type | Documentation Required |
|-------------|------------------------|
| New feature | Update relevant docs, add to README index |
| API change | Update `backend.md`, `frontend.md` |
| Scan pipeline change | Update `scan-lifecycle.md`, `tools-nmap-nuclei.md` |
| Data model change | Update `data-model.md`, `mermaid/data-model.mmd` |
| New `NucleiProfile` | Document in `tools-nmap-nuclei.md` |
| New scanner | Add to `extending-scanners.md`, update diagrams |
| Configuration change | Update relevant config docs |

### Diagram Updates

When workflow changes occur:
1. Update the relevant `.mmd` file in `docs/mermaid/`
2. Verify the diagram renders correctly (use https://mermaid.live)
3. Update any inline diagram copies in markdown files

### Documentation Style

- Use consistent terminology (see terminology table below)
- Put filenames in backticks: `scan_tasks.py`
- Put model names in backticks: `Port`, `Vulnerability`
- Use tables for structured information
- Add cross-links to related documentation

## Terminology Standards

| Term | Usage |
|------|-------|
| `ScanTarget` | Model name (backticks) |
| `Port` | Model name (backticks) |
| `ToolExecution` | Model name (backticks) |
| `Vulnerability` | Model name (backticks) |
| `ScanConfig` | Model name (backticks) |
| `NucleiProfile` | Dataclass for Nuclei profile mapping |
| `scan_mode` | Config field (`fast` or `deep`) |
| Frontend, Backend, Worker | Component names (capitalized) |
| Nmap, Nuclei | Tool names (capitalized) |

## Pull Request Checklist

- [ ] Code follows project style guidelines
- [ ] Tests pass locally
- [ ] Documentation updated if behavior changes
- [ ] Diagrams updated if workflow changes
- [ ] Commit messages follow conventional commits
- [ ] No secrets or credentials in code
- [ ] PR description explains the change and testing done

## Code Review Guidelines

Reviewers should check:
- Code quality and readability
- Test coverage for new functionality
- Documentation completeness
- Backward compatibility considerations
- Security implications (especially for scan-related changes)

## Getting Help

- Check existing documentation in `docs/`
- Review similar code patterns in the codebase
- Ask questions in PR comments
