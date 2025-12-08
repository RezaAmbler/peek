# TODO.md - PEEK V2 Roadmap & Known Issues

## Roadmap Phases

### Phase 1-4: Single-User Mode (Current)
Core scanning functionality is complete:
- Port discovery (Nmap/Masscan)
- Service detection
- Vulnerability scanning (Nuclei)
- SSH hardening analysis (ssh-audit)
- Historical comparison
- Report generation (PDF/HTML/CSV)
- Scheduled scans (Celery Beat)
- User authentication (JWT)

### Phase 2B: Pending Improvements
- [ ] **Celery task cancellation** - Currently only updates DB status, doesn't actually revoke the Celery task
  - Location: `backend/app/routers/scans.py:309`
  - Requires: Use `scan.celery_task_id` to call `celery.control.revoke()`

### Phase 5+: Multi-Organization Support
Infrastructure is stubbed but not activated:
- [ ] Activate `organization_id` filtering in queries
  - `backend/app/routers/scans.py:50` - NOTE comment marks the spot
- [ ] Implement organization model relationships
  - `backend/app/models/organization.py` - Placeholder exists
- [ ] Add organization-level permissions and billing

**Stubbed fields (all currently NULL):**
- `User.organization_id`
- `Scan.organization_id`
- `ScanConfig.organization_id`

---

## Known Bugs

| Priority | Issue | Location | Fix |
|----------|-------|----------|-----|
| High | Celery task cancellation is a no-op | `backend/app/routers/scans.py:309` | Implement `revoke()` call |
| Medium | `alert_on_critical` triggers on ANY vulns, not just critical | `backend/app/tasks/scheduled_scan_tasks.py:226` | Filter by severity before alerting |

---

## Feature Toggle Status

| Feature | Default | Enable Via | Notes |
|---------|---------|------------|-------|
| NSE Scripts | Off | `config/nse_profiles.yaml` + `NseProfileService.is_enabled()` | Nmap scripting engine |
| SSH-Audit | Off | `ScanConfig.enable_ssh_audit` | SSH hardening checks |
| Email/SMTP | Off | `settings.SMTP_ENABLED` | Scan completion notifications |
| ZAP | Off | `check_zap_available()` | OWASP ZAP web scanning |
| Nikto | Available | Not integrated in main pipeline | Web server scanning |
| SSLscan | Available | Via scan config | SSL/TLS assessment |

---

## Configuration Notes

### Nuclei Profiles (`config/nuclei_profiles.yaml`)
- Avoid broad tags like `tech` that match thousands of templates (causes timeouts)
- Service-specific tag combinations are more reliable
- Rate limits are per-profile to avoid overwhelming targets

### NSE Profiles (`config/nse_profiles.yaml`)
- Requires explicit enablement
- Scripts grouped by service type

---

## Tool Integration Status

| Tool | Status | Phase | Notes |
|------|--------|-------|-------|
| Nmap | Complete | Discovery + Service Detection | Core functionality |
| Nuclei | Complete | Vulnerability Scanning | Profile-based targeting |
| ssh-audit | Complete | SSH Analysis | Optional per-config |
| SSLscan | Complete | TLS Assessment | Optional |
| Masscan | Available | Fast Discovery | Alternative to Nmap discovery |
| Nikto | Available | Web Scanning | Not in main pipeline |
| OWASP ZAP | Available | Web App Testing | Requires ZAP daemon |

---

## Documentation

- `CLAUDE.md` - Development reference
- `NAR_OVERVIEW.md` - Narrative project overview
- `docs/` - Detailed documentation (scan lifecycle, architecture, data model)
