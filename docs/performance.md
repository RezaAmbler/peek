# Performance & Scaling

After reading this you'll understand:
- Bottlenecks in the PEEK pipeline and how to tune them.
- DB considerations (SQLite vs Postgres).
- Nmap and Nuclei tuning knobs.
- Celery and caching considerations.
- Recommendations for larger scans.

## Database Considerations

### SQLite (Default)

| Consideration | Notes |
|---------------|-------|
| Single-writer | Write locks can block concurrent writes (Worker vs API) |
| Concurrency | Keep scan orchestration mostly sequential or low-concurrency |
| Use case | Single-node dev/test; monitor for "database is locked" errors |

### When to Consider Postgres

- Higher concurrency needs
- Multiple Workers
- Larger datasets
- BI/reporting requirements
- Fewer lock issues; better for scaling read/write workload

## Nmap Tuning

| Aspect | Tuning Options |
|--------|----------------|
| Discovery | `--top-ports` vs full port scans; adjust scan rate/timeouts |
| Service detection | `nmap_args` (`-sT -sV -sC -T* -Pn`); tweak `-T` level (T2 conservative → T4 faster) |
| Parallelism | Current pipeline runs sequential per target (SQLite-friendly) |
| Timeouts | `host_timeout_seconds` slices into phases; ensure realistic values |

**Note**: On Docker Desktop (macOS), use `-sT` instead of `-sS` due to VM network translation.

## Nuclei Tuning

| Aspect | Tuning Options |
|--------|----------------|
| **Scope** | Tags/templates: `fast` mode uses targeted HTTP tags; `deep` mode is comprehensive |
| **Exclusions** | `excluded_templates` reduce noise and runtime |
| **Tag validation** | Skips runs with zero matching templates (saves time) |
| **Rate limit** | Per-profile `rate_limit` or default 150; lower for sensitive services (DB/LDAP) |
| **Timeout multiplier** | Per-profile scales `nuclei_timeout`; adjust `global_tool_timeout_seconds` |
| **Severity** | `nuclei_severity` controls what's emitted/stored; broader severities increase runtime |

## Celery Tuning

| Aspect | Notes |
|--------|-------|
| Concurrency | Adjust worker pool size if you move off SQLite; keep low with SQLite to avoid lock contention |
| Retries | Not heavily used today; consider retries for transient tool failures |
| Prefetch/acks | Default settings; tune for many small tasks or stricter delivery |

## Caching Strategies

| Cache | Purpose |
|-------|---------|
| Tag validation cache | `validate_tags_have_templates()` uses `lru_cache` to avoid repeated `nuclei -tl` calls |
| Template registry | Consider caching Nuclei template lists if extending validation |

**Clear cache**: Call `clear_tag_validation_cache()` when templates update.

## Bottlenecks & Diagnostics

| Issue | Cause | Mitigation |
|-------|-------|------------|
| Slow ports | DB/LDAP services have reduced rate limits | Watch Worker logs for timeouts |
| Slow Nuclei templates | Comprehensive scan mode | Use `fast` mode, add exclusions |
| Long-running tools | Insufficient timeouts | Adjust `nuclei_timeout`, `global_tool_timeout_seconds`, `host_timeout_seconds` |
| DB lock contention | High parallelism with SQLite | Reduce parallelism or migrate to Postgres |
| Network/IO saturation | High scan rate/parallelism | Tune cautiously |

## Recommendations for Larger Scans

| Recommendation | Description |
|----------------|-------------|
| Use Postgres | For concurrent Workers and larger data |
| Use `scan_mode=fast` | For initial sweeps; reserve `deep` for narrower targets |
| Tune `nuclei_severity` | Drop `info`/`low` for speed; include when completeness needed |
| Expand exclusions | For noisy templates; keep tag validation enabled |
| Scale Workers gradually | Monitor DB locks and CPU/IO |
| Monitor Worker logs | Tag validation warnings, tool timeouts, exclusions applied |

## Other Tool Tuning

| Tool | Tuning Options |
|------|----------------|
| httpx | `httpx_timeout`, disable `httpx_screenshots` for speed |
| Katana | Reduce `katana_max_depth` for fewer endpoints |
| testssl.sh | Disable `enable_testssl` for faster scans (2-5 min per host) |
| Nikto | Reduce `nikto_timeout` for quicker web scans |
| ZAP | Reduce `zap_timeout`; baseline scan is lighter than full scan |

## Related Documentation

- **Backend**: [`backend.md`](backend.md) — Celery tasks, tool wrappers
- **Tool documentation**: [`tools/`](tools/) — Individual tool guides
- **Troubleshooting**: [`troubleshooting.md`](troubleshooting.md) — Common issues
