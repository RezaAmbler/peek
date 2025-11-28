# Performance & Scaling

After reading this you’ll understand:
- Bottlenecks in the PEEK pipeline and how to tune them.
- DB considerations (SQLite vs Postgres).
- Nmap and nuclei tuning knobs.
- Celery and caching considerations.
- Recommendations for larger scans.

## Database considerations
- **SQLite** (default):
  - Single-writer: write locks can block concurrent writes (Celery worker vs API updates).
  - Safer to keep scan orchestration mostly sequential or low-concurrency when writing heavily.
  - Good for single-node dev/test; monitor for “database is locked” errors under load.
- **When to consider Postgres**:
  - Higher concurrency, multiple workers, larger datasets, or BI/reporting needs.
  - Fewer lock issues; better for scaling read/write workload.

## Nmap tuning
- Discovery vs service detection:
  - Discovery: top ports (`--top-ports`) vs full port scans; adjust `masscan_rate`/timeouts if using masscan alternatives.
  - Service detection: `nmap_args` (`-sS -sV -sC -T* -Pn`); tweak `-T` level (T2 conservative → T4 faster), port list, and timeout percentages (`nmap_timeout_percent`).
- Parallelism:
  - Current pipeline runs sequential per target (SQLite-friendly). More parallelism increases speed but adds DB contention and CPU/IO load.
- Timeouts:
  - `host_timeout_seconds` slices into phases; ensure realistic values for slow networks.

## Nuclei tuning
- Scope:
  - Tags/templates: fast mode uses targeted HTTP tags; deep mode (empty tags) is comprehensive.
  - Exclusions: `excluded_templates` reduce noise and runtime.
  - Tag validation skips runs with zero matching templates (saves time).
- Rate-limit/concurrency:
  - Per-profile `rate_limit` or default 150; lower for sensitive services (DB/LDAP) to reduce impact.
  - Timeout multiplier per profile scales `nuclei_timeout`; adjust `global_tool_timeout_seconds` if needed.
- Severity:
  - `nuclei_severity` controls what’s emitted/stored; broader severities (including low/info) increase runtime/output size.

## Celery tuning
- Concurrency: Adjust worker pool size if you move off SQLite; with SQLite, keep low to avoid lock contention.
- Retries: Not heavily used today; consider retries for transient tool failures if needed.
- Prefetch/acks: Default settings; tune if you have many small tasks or want stricter delivery semantics.

## Caching strategies
- Tag validation cache (`validate_tags_have_templates` lru_cache): Avoids repeated nuclei `-tl` invocations for the same tag sets; clear when templates update.
- Template registry: Consider caching nuclei template lists if you extend validation; today only tag validation is cached.

## Bottlenecks & diagnostics
- **Slow ports**: Certain services (DBs, LDAP) have reduced rate limits; watch worker logs for timeouts.
- **Slow nuclei templates**: Use exclusions or targeted tags (fast mode); review nuclei logs/output size in ToolExecution.
- **Long-running tools**: Adjust timeouts (`nuclei_timeout`, `global_tool_timeout_seconds`, `host_timeout_seconds`) and profile multipliers.
- **DB lock contention**: With SQLite, avoid high parallelism; consider Postgres for heavier loads.
- **Network/IO**: High `masscan_rate`/`nmap` parallelism can saturate network; tune cautiously.

## Recommendations for larger scans
- Move to Postgres for concurrent workers and larger data.
- Use `scan_mode=fast` for initial sweeps; reserve `deep` for narrower targets or follow-ups.
- Tune `nuclei_severity` (e.g., drop info/low for speed, include when you need completeness).
- Expand exclusions for noisy templates; keep tag validation enabled to skip empty sets.
- Scale Celery workers gradually; monitor DB locks and CPU/IO.
