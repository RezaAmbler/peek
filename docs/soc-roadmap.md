# SOC Operability Roadmap

After reading this you'll understand:
- What the SOC-operability assessment found and which recommendations are shipping in this pass vs. designed-only here.
- The fingerprint + `FindingState` foundation landing now, and how each remaining recommendation builds on it.
- Concrete data-model/endpoint/service sketches for recommendations #5-#9, ready to scope into future work.
- Rough effort and sequencing so this can be planned into subsequent milestones.

## Background

A SOC-operability assessment against PEEK produced 9 recommendations. This pass (branch `soc-hardening`) implements the first four in code:

1. A quick-win alert bug fix.
2. Stable finding fingerprints + de-noised scan comparison.
3. Risk enrichment (CVSS/EPSS/KEV) on findings.
4. A cross-scan triage lifecycle via a new `FindingState` table keyed by a stable `fingerprint`, plus one outbound webhook/Slack push on state change.

This document is the committed **design** (no code) for the remaining five recommendations, #5-#9. Each is written to build explicitly on the fingerprint + `FindingState` foundation landing now, rather than duplicating it. None of the sketches below are implemented; they're scoped closely enough to pick up as follow-on work without re-litigating the shape.

### The foundation these designs build on

`FindingState` (landing this pass) gives PEEK its first notion of a finding that persists *across* scans instead of being re-derived per comparison. Today, `Vulnerability` rows are scan-scoped (`scan_target_id`, `tool_execution_id`) and `comparison_service.py` computes "new vs. fixed" on demand by diffing two scans' `Vulnerability` sets with an in-memory key (`ip:template_id:port`) — nothing about a finding's history is stored. `FindingState` changes that: it's keyed by a stable `fingerprint` (independent of `scan_id`) and carries `first_seen_at`, `last_seen_at`, `status` (new/triaged/acknowledged/resolved/false_positive), and the risk-enrichment fields from #3. Every recommendation below either reads that table, writes to it, or depends on the identity stability it introduces.

## Recommendations covered here

| # | Recommendation | Depends on foundation for |
|---|-----------------|---------------------------|
| 5 | Trend & SLA metrics | `first_seen_at`/`last_seen_at`/`status` as the sole source of finding age and MTTR |
| 6 | AuthN/Z hardening | Mostly independent; RBAC roles gate who can write to `FindingState` |
| 7 | Scope authorization + audit log | Mostly independent; audit log uses `fingerprint` as a stable resource id |
| 8 | Performance & scale | Delta scanning needs fingerprints to detect "unchanged since last scan" |
| 9 | First-class asset model | Inverse dependency — re-keys `FindingState` off `asset_id` instead of IP |

---

## #5 Trend & SLA metrics

**Problem.** PEEK's only cross-scan view today is `ComparisonService.compare_scans`, a pairwise, on-demand diff between exactly two scans (`backend/app/services/comparison_service.py`). It answers "what changed between these two runs" but not "how long has this finding existed," "how fast do we fix criticals," or "did we breach our remediation SLA" — there's no persisted timeline, because `Vulnerability` rows have no identity beyond a single scan. Nothing in the schema today can express finding age or recurrence.

**Sketch.**

- New service `TrendMetricsService` (`backend/app/services/trend_metrics_service.py`) computing aggregates directly off `FindingState`:
  - **MTTR** — `resolved_at - first_seen_at`, grouped by severity, from `FindingState` rows where `status = 'resolved'`.
  - **Finding age** — `now() - first_seen_at` for rows where `status not in ('resolved', 'false_positive')`, bucketed into a histogram.
  - **Recurrence** — a `FindingState.reopened_count` counter (incremented whenever a fingerprint transitions `resolved -> new` on a later scan) plus a lightweight `FindingStateTransition` log (`id`, `finding_state_id`, `from_status`, `to_status`, `changed_at`, `changed_by_id`) for auditability of the transition itself.
  - **SLA breach** — a per-severity threshold table `SlaPolicy` (`organization_id`, `severity`, `max_age_days`), evaluated against open findings whose age exceeds the threshold.
- Nightly Celery Beat task `recompute_finding_metrics` rolls the above into a small materialized table `FindingMetricsDaily` (`date`, `organization_id`, `config_id`, `severity`, `open_count`, `mean_age_days`, `sla_breach_count`) so dashboard reads stay cheap instead of aggregating over all of `FindingState` per request.
- API: `GET /api/metrics/trends?config_id=&window=90d` returning MTTR/age/recurrence series; `GET /api/metrics/sla-breaches?organization_id=` returning the current breach list for a triage queue.
- Frontend: new "Trends" dashboard route alongside the existing comparison view — age histogram, MTTR trend line, SLA breach table, reusing the chart components already used for comparison summaries.

**Dependency on foundation.** Fully load-bearing — every metric here is a derivation of `FindingState.first_seen_at` / `last_seen_at` / `status`. None of it is expressible against today's scan-scoped `Vulnerability` table.

**Effort/sequencing.** Small-medium, ~3-5 days. This is the natural first pickup after `FindingState` ships: it's read-only aggregation with one new write path (the nightly rollup job), so it can't destabilize the triage lifecycle it depends on.

---

## #6 AuthN/Z hardening

**Problem.** `create_default_admin()` in `backend/app/main.py` seeds a literal `admin`/`admin` superuser (`username="admin"`, `hashed_password=get_password_hash("admin")`, `is_admin=True`) on every startup if the user doesn't already exist, with no forced rotation — a live default credential in any deployment that skips manual cleanup. Authorization is a single `User.is_admin` boolean (`backend/app/models/user.py`) with no scoped roles — analysts, viewers, and auditors all get the same binary. Auth is bespoke JWT via `python-jose` (`backend/app/core/security.py`), issuing one `ACCESS_TOKEN_EXPIRE_MINUTES`-lived access token with no refresh flow, no SSO, and no MFA.

**Sketch.**

- **Bootstrap fix (independent, do first).** Gate `create_default_admin()` behind `User.must_change_password = True` and a `force_password_reset_at` timestamp; the login response signals the frontend to route straight to a password-change screen. Support `ADMIN_BOOTSTRAP_PASSWORD` env var so the seeded password isn't hardcoded as `"admin"` in any environment.
- **RBAC.** Replace `is_admin` with `Role` (`id`, `name`, `permissions` JSON) and `UserRole` (`user_id`, `role_id`, `organization_id`) tables; seed `admin`, `analyst`, `viewer`, `auditor`. Add a `require_permission("scan:create")`-style FastAPI dependency in `backend/app/api/deps.py` to replace scattered `is_admin` checks across routers.
- **SSO (OIDC/SAML).** New `AuthProvider` table (`id`, `organization_id`, `provider_type`, `issuer`, `client_id`, `client_secret_encrypted`, `enabled`); routes `POST /api/auth/sso/{provider_id}/login`, `GET /api/auth/sso/{provider_id}/callback`, backed by `authlib`.
- **MFA.** TOTP via `User.mfa_secret_encrypted` / `User.mfa_enabled`; routes `POST /api/auth/mfa/enroll`, `POST /api/auth/mfa/verify`.
- **Shorter JWTs + refresh.** Migrate `python-jose` (`backend/requirements.txt: python-jose[cryptography]==3.5.0`) to `PyJWT` — this migration is already queued. Shrink access-token TTL to ~15 minutes; add a `RefreshToken` table (`id`, `user_id`, `token_hash`, `expires_at`, `revoked_at`, `replaced_by_id`) with rotate-on-use; routes `POST /api/auth/refresh`, `POST /api/auth/logout` (revokes).

**Dependency on foundation.** Mostly independent — this track is about identity, not findings. The one link: once RBAC roles exist, they should gate `FindingState` write endpoints (ack/resolve/reassign/snooze) so triage actions aren't left `is_admin`-gated as a permanent stopgap. RBAC should land before or alongside any further hardening of those triage routes.

**Effort/sequencing.** Largest item in this roadmap — Large, ~3-4 weeks total, but splits into independently shippable slices: (1) admin bootstrap + forced rotation, quick, do immediately; (2) RBAC roles, ~1 week; (3) JWT/refresh migration, ~3-5 days, parallelizable with RBAC; (4) OIDC/SAML SSO, ~1.5-2 weeks, largest surface area, sequence last; (5) MFA, ~1 week, pairs naturally with SSO.

---

## #7 Scope authorization + immutable audit log

**Problem.** `ScanConfig.targets` is a free-form JSON array of IPs/hostnames — any user with scan-create access can populate it and immediately launch the full 11-tool pipeline (Nmap, Nuclei, Nikto, ZAP, ssh-audit, etc.) against those targets. There is no allowlist, no approval gate, and no check that a target is in-scope for the caller's organization. There's also no durable record of who scanned what and when beyond the mutable `Scan`/`ScanTarget` rows themselves, which can be edited or deleted.

**Sketch.**

- `ScopeAllowlist` table: `id`, `organization_id`, `cidr_or_hostname_pattern`, `label`, `approved_by_id`, `approved_at`, `expires_at`, `max_concurrent_scans`, `rate_limit_per_hour`.
- New service `ScopeAuthorizationService.check_targets(targets, organization_id)`, called from `POST /api/scan-configs` and `POST /api/scans/{id}/start`. Unmatched targets are hard-rejected by default, or routed into an approval workflow: `ScopeApprovalRequest` table plus `POST /api/scope-requests`, `GET /api/scope-requests`, `POST /api/scope-requests/{id}/approve`.
- Blast-radius/rate controls: `ScanConfig.max_targets_per_scan` and an org-level `concurrent_scan_limit`, enforced at scan-start / Celery dispatch time in `backend/app/tasks/scan_tasks.py`, rejecting or queuing requests over the limit.
- `AuditLog` table, append-only (no update/delete route exposed; DB-level trigger or ORM `before_update`/`before_delete` guard rejects mutation): `id`, `occurred_at`, `actor_user_id`, `action` (e.g. `scan.start`, `scope.approve`, `finding.resolve`), `resource_type`, `resource_id`, `target_summary` (JSON), `actor_ip_address`, `request_id`. Written via a small `AuditLogger.record(...)` helper called from the scans, scan-configs, scope-requests, and (once it exists) finding-state routers. Read endpoint `GET /api/audit-log?actor=&action=&from=&to=`, restricted to `auditor`/`admin` roles from #6.

**Dependency on foundation.** Scope authorization itself is independent — it gates scan *creation*, upstream of findings entirely. The audit log has one loose coupling: once `FindingState` triage actions are audited, `fingerprint` is the natural `resource_id` for `finding.status_changed` events, since it's the only identifier that survives across the scans a finding appears in — logging against `scan_target_id` would fragment the trail per scan.

**Effort/sequencing.** Medium, ~1.5-2 weeks. Sequence: audit log first (~3-4 days — foundational, additive-only, low risk), then blast-radius/rate limits (~2-3 days — mostly config fields plus a dispatch-time check), then scope allowlist + approval workflow (~1 week — has real UI and workflow surface).

---

## #8 Performance & scale

**Problem.** `docs/performance.md` documents today's pipeline as sequential per target ("Current pipeline runs sequential per target (SQLite-friendly)"), and a single host through the full 12-phase, 11-tool pipeline takes roughly 36 minutes. Multiple `ScanTarget`s within one `Scan` aren't fanned out across workers, and every scan re-runs every tool at full depth regardless of whether anything about the target changed since the last run.

**Sketch.**

- **Parallel target fan-out.** Today's Celery orchestration (`backend/app/tasks/scan_tasks.py`) processes `ScanTarget`s sequentially inside one task chain. Split into per-target `celery.group`/`chord` tasks so N targets in a `Scan` run concurrently, bounded by a new `ScanConfig.max_parallel_targets` and worker capacity. Requires moving off SQLite to Postgres per `docs/performance.md`'s own concurrency caveat ("Single-writer... keep scan orchestration mostly sequential").
- **Incremental/delta scanning.** New `config_snapshot.scan_strategy = "full" | "delta"`. On a delta run, a cheap pre-flight phase (discovery-only Nmap) computes the fingerprint each candidate finding *would* have and diffs it against `FindingState` rows already `last_seen` for that target; ports/services whose fingerprint-relevant surface is unchanged skip the expensive phases (Nuclei/Nikto/ZAP/testssl) and just bump `FindingState.last_seen_at`/`last_scan_id` for findings still present. New service `DeltaScanPlanner` (`backend/app/services/delta_scan_planner.py`) invoked at pipeline start.
- **Scan windows.** `ScanConfig.allowed_window_start` / `allowed_window_end` (or cron-style blackout ranges), enforced by Celery Beat and the scan-start endpoint, deferring or queuing starts outside the window — protects production targets from scans during business hours.
- **Distributed workers.** Split Celery queues by phase weight — `queue=heavy` for Nuclei/ZAP/testssl, `queue=light` for httpx/ssh-audit — so lightweight and heavyweight phases don't head-of-line block each other; document worker autoscaling (`celery worker --autoscale`) once on Postgres.

**Dependency on foundation.** Delta scanning is the one piece directly built on the foundation — it needs stable fingerprints to determine "is this the same finding as last time" without re-running the tool, and `FindingState.last_seen_at` to decide what's stale enough to warrant a full re-probe. Parallel fan-out, scan windows, and distributed workers are orchestration changes independent of `FindingState`.

**Effort/sequencing.** Large overall, ~3-4 weeks. Sequence the independent, lower-risk pieces first: (1) parallel target fan-out, ~1 week, biggest win for multi-host configs; (2) scan windows, ~2-3 days; (3) queue-splitting/distributed workers, ~1 week; (4) delta scanning, ~1-1.5 weeks, last — it depends on fingerprints/`FindingState` having soaked in production first, since shipping delta scanning too early risks silently skipping genuine changes on an unproven identity scheme.

---

## #9 First-class asset model

**Problem.** PEEK has no concept of an "asset." `Vulnerability.host` and `ScanTarget.ip_address` are the only identity a finding has, and IPs are ephemeral (DHCP, cloud re-IP, NAT). `ComparisonService._vuln_key` keys directly on `f"{ip}:{template_id}:{port}"` — a host that changes IP between scans looks like its old vulnerabilities were "fixed" and a new host "appeared" with the same issues. There's no ownership, tags, or business-criticality anywhere in the schema; `ScanTarget` (`backend/app/models/scan_target.py`) carries only `device_name` and `ip_address`.

**Sketch.**

- `Asset` table: `id`, `organization_id`, `name`, `primary_identifier` (hostname/MAC/cloud-instance-id — whichever is most stable for the environment), `ip_history` (JSON array of `{ip, first_seen_at, last_seen_at}`), `owner_user_id`, `owner_team`, `tags` (JSON), `business_criticality` (critical/high/medium/low), `environment` (prod/staging/dev), `created_at`, `updated_at`, `decommissioned_at`.
- `AssetIdentityResolver` service (`backend/app/services/asset_identity_resolver.py`), run at `ScanTarget` creation: given an incoming IP plus any hostname/banner hints from that run, match to an existing `Asset` (by hostname, MAC where discoverable, or IP-history overlap) or create a new one. `ScanTarget` gains a nullable `asset_id` FK, backfilled by a one-time migration.
- API: `POST/GET/PATCH /api/assets`, `GET /api/assets/{id}/history` (every scan/finding ever tied to this asset regardless of IP churn), `GET /api/assets/{id}/findings`.
- **Re-keying `FindingState`.** `FindingState.asset_id` becomes the durable join key alongside (eventually instead of) `scan_target_id`. Fingerprint computation moves from IP-anchored to asset-anchored: `fingerprint = hash(asset_id, template_id, port, normalized_matched_at)`. This is a breaking change to the fingerprint formula shipping in this pass, so it should be planned explicitly as **fingerprint v2** with a one-time recompute migration once assets exist, not silently swapped in.

**Dependency on foundation.** Inverse of the others — `Asset` doesn't depend on `FindingState`, but `FindingState` depends on `Asset` once this ships. The fingerprint/`FindingState` work landing now is necessarily IP/`ScanTarget`-anchored, because no `Asset` table exists yet; this recommendation is explicitly the follow-up that re-keys the foundation to close the IP-churn blind spot the assessment flagged.

**Effort/sequencing.** Large, ~3 weeks. Sequence deliberately: land `Asset` + identity resolution first as an additive, non-breaking layer (~1.5 weeks) with `asset_id` nullable everywhere; then do the fingerprint v2 re-keying migration as its own careful pass (~1 week) once asset coverage is high (e.g., >90% of active targets resolved) to avoid a mass "new finding" noise spike on cutover day.

---

## Sequencing summary

| Order | Recommendation | Effort | Why this order |
|-------|-----------------|--------|-----------------|
| 1 | #5 Trend & SLA metrics | Small-medium (~3-5 days) | Read-only on `FindingState`; safest first pickup once the foundation lands |
| 2 | #7 Scope authorization + audit log | Medium (~1.5-2 weeks) | Mostly independent of `FindingState`; closes an active safety gap (unrestricted scan targets) |
| 3 | #6 AuthN/Z hardening | Large (~3-4 weeks) | Mostly independent; the credential-rotation slice should move up opportunistically as a quick win |
| 4 | #8 Performance & scale | Large (~3-4 weeks) | Delta scanning needs `FindingState` proven in production first; other sub-items can start earlier |
| 5 | #9 First-class asset model | Large (~3 weeks) | Re-keys the foundation itself — highest blast radius, do last and deliberately |

## Related Documentation

- **Data model**: [`data-model.md`](data-model.md) — current entities this roadmap builds on
- **Architecture**: [`architecture.md`](architecture.md) — component overview
- **Performance**: [`performance.md`](performance.md) — current bottlenecks referenced in #8
- **Backend internals**: [`backend.md`](backend.md) — Celery tasks, routers, services layout
