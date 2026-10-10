# Scan-Tool Review — 2026-10

- **Agent:** `scan-tool-reviewer` (Claude Code project subagent)
- **Date:** 2026-10-10
- **Commit reviewed:** `7b9c488` (fix(backend): use bcrypt directly, drop passlib; dispose test engines; bump scanners)
- **Branch:** `review/scan-security-2026-10`
- **Scope:** `backend/Dockerfile.celery` and the scanner version bumps in `7b9c488`; scan-tool integration code generally (`backend/app/tools/*`, `backend/app/parsers/*`, `backend/app/tasks/scan_tasks.py`)
- **Verdict:** NEEDS WORK
- **Mode:** read-only review; no code was modified

> Findings below are the agent's report, lightly reformatted. Version compatibility is **mostly unverified**: the sandbox could not run the new binaries and the agent did not read their changelogs. The one upstream check made was an HTTP HEAD request, which returned 200 for the nuclei 3.11.1, httpx 1.12.0 and nmap 7.991 download URLs. Line references prefixed with `~` are approximate, as given by the agent.

## Severity summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 1 |
| Medium | 5 |
| Low | 5 |
| Info | 6 |

## Critical

None.

## High

### H1. A failed nuclei run (or nikto/masscan run) is recorded as a clean scan with zero findings

- **Where:** `backend/app/tools/nuclei.py:51-52` and `backend/app/tools/nuclei.py:95-110` for `run_nuclei`; `backend/app/tools/nuclei.py:150-197` for `run_nuclei_list`; `backend/app/tools/nikto.py:~39-82`; `backend/app/tools/masscan.py:~26-62`
- **Status:** verified in code
- **What is wrong:**
  - The output path comes from `tempfile.NamedTemporaryFile(delete=False)`, so the file already exists, empty, before the tool starts.
  - After `subprocess.run`, the code never checks `returncode`. `output_path.exists()` is always true.
  - Empty output is then mapped to success: nuclei returns `(True, "", None)`, nikto returns `(True, None, "Empty output")`, and masscan returns `[]`.
- **Impact:**
  - This matters most for the bump from nuclei 3.6.2 to 3.11.1.
  - If any flag the code passes is renamed or removed, or templates are missing or incompatible, nuclei exits non-zero with an empty file.
  - The `ToolExecution` row then shows `exit_code=0` and no error, and the scan reports "no vulnerabilities". That is a silent false negative.
  - The flags used are `-jsonl-export`, `-omit-raw`, `-no-interactsh`, `-silent`, `-no-color`, `-severity`, `-tags`, `-exclude-templates`, `-list` and `-rate-limit`. These could not be verified against 3.11.1.
- **Fix:**
  - Capture `returncode` and `stderr` and return them to the caller. Treat a non-zero exit as failure when the output is empty, and store `stderr` in `ToolExecution.error_message`.
  - Use `mkdtemp` and a path that does not exist yet, as httpx and testssl do.
  - Add a startup smoke test, for example `nuclei -version` plus a dry run, to the image build or the health check.
- **Resolution: fixed** — commits `6b419a4` (runners) and `e8a1fb1` (phases).
  - `backend/app/tools/base.py`: `run_command()` records the exact command line, the real exit code, stderr and timeout / missing-binary state. `failure_reason()` turns a non-zero exit, timeout or missing binary into an error message with the stderr excerpt.
  - Every runner now uses it: `nuclei.py` (`run_nuclei`, `run_nuclei_list`), `nikto.py`, `masscan.py`, `nmap.py` (`run_nmap`, `run_nmap_discovery`), `nmap_nse.py`, `sslscan.py`, `ssh_audit.py`, `httpx.py`, `katana.py`, `testssl.py`, `zap.py`. Output goes to a path inside a fresh temp directory that does not exist before the run.
  - nuclei: success is decided by the exit code. Checked in the v3.11.1 source: fatal errors exit 1, and the JSONL export is written on clean shutdown even with zero results, so only "exit 0 + empty export" means no findings.
  - nikto: a non-zero exit, an empty report, invalid JSON or a report with zero host records is a failure. masscan: only "exit 0 + empty report" means no open ports.
  - Related false-negative path found while fixing this: `validate_tags_have_templates()` in `services/service_profile.py` treated a failed `nuclei -tl` (empty stdout) as "no templates for these tags" and the port was skipped without a `ToolExecution`. A failed listing now assumes the tags are valid so the real run happens and fails visibly.
  - `ToolExecution` rows get `exit_code` (real code; 124 timeout, 127 not installed) and `error_message` through `record_tool_result()` in `tasks/scan_tasks.py`. A failed discovery marks the target `failed` instead of "0 open ports".
  - The "startup smoke test" part is in the image build (`backend/Dockerfile.celery`, last `RUN`): binaries must start and `nuclei -tl` must load templates. **deferred-needs-live-scanner-test**: the image has not been built.
  - Tests: `backend/tests/test_tool_runners.py`, `test_scan_phases.py`.

## Medium

### M1. Scanner pins are not reproducible or verified

- **Where:** `backend/Dockerfile.celery:1`, `:11`, `:33`, `:38`, `:48`, `:55`, `:68`
- **Status:** verified in code
- **What is wrong:**
  - The zips and the nmap tarball are downloaded over HTTPS with no SHA-256 check.
  - nikto and testssl are cloned by tag (`--branch 2.6.1`, `--branch v3.2.4`), and tags can move. There is no commit SHA.
  - The base image is `python:3.13-slim`, a floating tag with no digest.
  - `nuclei -update-templates` (`backend/Dockerfile.celery:45`) pulls whatever the templates repo holds at build time. The template set therefore changes on every rebuild, even though the binary is pinned.
- **Impact:** Two builds of the same commit can scan differently. The supply chain for tools that run as root with sudo is only as trustworthy as GitHub and nmap.org on build day.
- **Fix:**
  - Add `echo "<sha256>  file" | sha256sum -c -` for each download. Pin git clones with `git checkout <sha>`. Pin the base image by digest.
  - Pin the templates to a release tag, or document that they are intentionally floating.
- **Resolution: fixed** (not built — see live checklist) — commit `f980045`, `backend/Dockerfile.celery`.
  - Base image pinned by digest: `python:3.13-slim@sha256:70729b46…8c2f` (the multi-arch index for `3.13-slim` = `3.13-slim-trixie`, read from the registry API on 2026-10-10).
  - nmap 7.991 tarball: SHA-256 `a5d507f2…29be`, from `https://nmap.org/dist/sigs/nmap-7.991.tar.bz2.digest.txt`.
  - nuclei 3.11.1, httpx 1.12.0, katana 1.8.0 zips: SHA-256 for amd64 and arm64 copied from the upstream release checksum files (`nuclei_3.11.1_checksums.txt`, `httpx_1.12.0_checksums.txt`, `katana-1.8.0-checksums.txt`).
  - nikto `2.6.1` → commit `d201dac3…`, testssl.sh `v3.2.4` → commit `97763a41…`; the build fails if the tag resolves to another commit.
  - Templates: `nuclei -update-templates` replaced by `nuclei-templates` `v10.5.0` at commit `f8b8b8dc…`. Every nuclei call passes `-disable-update-check`; without it nuclei 3.x installs newer templates at scan time (checked in `internal/runner/runner.go` / `pkg/installer/template.go`).
  - **Not pinned:** Debian packages installed with apt (masscan, sslscan, chromium, perl modules). Stated in the Dockerfile header.

### M2. Large version jumps with no verified compatibility

- **Where:** `backend/Dockerfile.celery` (bumps in `7b9c488`); `backend/app/tools/httpx.py:~71-112`; `backend/app/tools/katana.py:~77-95`; `backend/app/parsers/httpx_parser.py`; `parse_nuclei_output`
- **Status:** version changes verified in the diff; upstream behaviour **unverified**
- **Versions changed in `7b9c488`:**

  | Tool | From | To |
  |---|---|---|
  | nmap | 7.98 | 7.991 |
  | nuclei | 3.6.2 | 3.11.1 |
  | httpx | 1.7.4 | 1.12.0 |
  | katana | 1.1.0 | 1.8.0 |
  | nikto | 2.6.0 | 2.6.1 |
  | testssl.sh | 3.2.3 | 3.2.4 |

- **What is wrong:** The nuclei, httpx and katana jumps are large, and no upstream behaviour could be verified.
- **Flags the repo depends on:**
  - httpx (`backend/app/tools/httpx.py:~71-112`): `-json -silent -nc -timeout -retries -sc -cl -ct -title -server -hash md5 -o -fr -maxr -td -tls-probe -jarm -cdn -ss -srd -ssw -vhost`
  - katana (`backend/app/tools/katana.py:~77-95`): `-jsonl -silent -nc -d -c -rate-limit -timeout -field-scope rdn -o -headless -automatic-form-fill`
- **Parser fields at risk (unverified):**
  - `backend/app/parsers/httpx_parser.py` reads `status_code`, `tech`, `webserver`, `hash`, `tls`, `chain`, `vhost` and `time`.
  - `parse_nuclei_output` reads `template-id`, `info.*`, `matched-at`, `extracted-results` and `curl-command`.
- **Impact:** A rename or format change would degrade results silently, because the parsers use `.get()` and return `None` or empty values.
- **Fix:** Run each tool once in the new image against a test host and save the JSON as fixtures (see M5). Keep the fixtures under `backend/tests/`.
- **Resolution: fixed for what source review can show; behaviour on a live target is deferred-needs-live-scanner-test** — commit `6b419a4`.
  - Method: the source of each pinned tag was downloaded from GitHub and the flag definitions and JSON struct tags were read (no binary was executed). Details are in `docs/tools/httpx.md`, `docs/tools/katana.md` and `docs/tools/nuclei.md` ("Verified against …").
  - **httpx v1.12.0 — mismatches found and fixed** (`backend/app/tools/httpx.py`):
    - `-ssw` does not exist. With screenshots enabled httpx would have exited with "flag provided but not defined". Now `-st <n>s`.
    - Screenshots are written to `<srd>/screenshot/<host>/<hash>.png`; the old non-recursive `*.png` glob never found them.
    - `-tls-probe` also probes every hostname in the certificate (off-target). Replaced by `-tls-grab`, which fills the same `tls` object.
    - `chain` is only emitted with `-include-chain`, and its items are objects, not URLs.
    - JSON: `jarm_hash` (parser read `jarm`), `cdn` is a boolean with `cdn_name`/`cdn_type`, `vhost` is a boolean (the phase called `len()` on it), `tls.tls_version`.
    - All other flags (`-u -json -silent -nc -timeout -retries -sc -cl -ct -title -server -hash -o -fr -maxr -td -jarm -cdn -ss -srd -vhost`) exist unchanged.
  - **katana v1.8.0 — mismatches found and fixed** (`backend/app/tools/katana.py`):
    - `-timeout` is the per-request timeout; the overall budget is `-crawl-duration`. PEEK passed its 120 s overall budget as the per-request timeout.
    - No `content_type` field (it is `response.headers["content-type"]`); `depth` is not serialised.
    - `-omit-raw -omit-body` added so raw responses and bodies are not stored.
    - `-u -jsonl -silent -nc -d -c -rate-limit -field-scope -o -headless -automatic-form-fill` exist unchanged.
  - **nuclei v3.11.1 — no mismatch**: all flags and the parsed JSON fields (`template-id`, `info.*`, `matched-at`, `extracted-results`, `curl-command`, `type`, `host`) are unchanged.
  - **nikto 2.6.1 — two defects found** (not part of the original finding): the JSON report is a list of host records, which the parser turned into one bogus finding per host while dropping the real ones (fixed in `backend/app/tools/nikto.py`); and nikto 2.6.x exits at startup without the Perl module `XML::Writer`, which the image did not install (fixed in the Dockerfile).
  - nmap 7.991 and testssl.sh 3.2.4: changelogs were not reviewed; **deferred-needs-live-scanner-test**.
  - Fixtures: the samples in `backend/tests/test_tool_parsers.py` are built from the upstream struct definitions, **not captured from a live run**. Capturing real output is on the live checklist.

### M3. Screenshots and headless crawling cannot work in this image

- **Where:** `backend/Dockerfile.celery` (no chromium installed; grep for `chrom` finds nothing); `backend/app/tools/httpx.py:~104-108` (`-ss`); `backend/app/tasks/scan_tasks.py:1004`
- **Status:** verified (no browser installed); consequence unverified
- **What is wrong:**
  - httpx `-ss` and katana `-headless` need a Chromium-class browser.
  - The scan phase hard-codes `headless=False` for katana (`scan_tasks.py:1004`), so only the httpx screenshots option is affected.
- **Impact:** Opting in to screenshots produces failed `ToolExecution` rows.
- **Fix:** Install chromium, or hide the option in the UI and API.
- **Resolution: fixed by installing Chromium; deferred-needs-live-scanner-test** — commits `f980045` (image) and `6b419a4` (runner).
  - Decision: keep the feature. Screenshots are opt-in (`httpx_screenshots`, default off) and already wired through the API, storage and UI, so the image now installs Debian's `chromium` (plus `fonts-liberation`).
  - httpx is told to use it (`-system-chrome`) and never downloads a browser at scan time. Chromium runs with `--no-sandbox` because its sandbox cannot start for an unprivileged user inside the container; the container is the isolation boundary. Documented in `docs/tools/httpx.md`.
  - `--build-arg INSTALL_CHROMIUM=false` builds without it (about 350 MB smaller). A screenshot run then fails visibly on its `ToolExecution` ("the chrome browser is not installed").
  - katana `-headless` uses the same browser (`-system-chrome -no-sandbox`); the phase still runs with `headless=False`.

### M4. Exception and timeout handling in the phases is inconsistent, and `ToolExecution` is not always finalised

- **Where:** `backend/app/tasks/scan_tasks.py:246-250`, `:471`, `:672`, `:1259-1262`, `:1332-1338`, `:1579`, `:1698`, `:1857`, `:1958-1964`
- **Status:** verified in code for each point below
- **What is wrong:**
  - **No `db.rollback()` in generic handlers.**
    - The only rollbacks are at `scan_tasks.py:471` and `:672`.
    - The per-tool `except Exception` blocks (nuclei `:1332-1338`, testssl `:1958-1964`, and the httpx, katana, nikto, zap and nse equivalents) commit on a session that may be in a failed-flush state.
    - The outer handler (`:246-250`) also commits `FAILED` without a rollback.
    - A failed flush inside a phase can therefore leave the scan stuck in `RUNNING` or raise `PendingRollbackError`.
  - **Exception paths do not set `raw_output`, and some do not set `duration_ms`.** Examples are `:1334-1337` and `:1960-1963`.
  - **`exit_code` is only 0 or 1.**
    - A timeout and a missing binary look the same as a tool error. The real return code is never stored.
    - Timeouts are reported as `success=False` with a message string only. The `ToolExecution` model has no timeout marker.
  - **Several fixed `command_line` strings do not match what ran.**
    - Nuclei (`:1259-1262`), testssl (`:1857`, which hard-codes `--fast` and omits `--sneaky` and the timeouts), nse (`:1579`) and sslscan (`:1698`) are all approximations.
    - Contract item 4 asks for the exact command line. The runners build the real `cmd` but do not return it.
- **Fix:** Have runners return `(cmd, returncode, stdout, stderr)` or a result dataclass. Have one shared helper create, finalise and roll back `ToolExecution` in a `try/except/finally`.
- **Resolution: fixed** — commit `e8a1fb1`, `backend/app/tasks/scan_tasks.py`.
  - **Rollback:** every per-tool `except` block calls `fail_tool_exec()`, which runs `db.rollback()` before writing. The outer handler in `run_scan` rolls back, closes every `ToolExecution` of the scan that never finished (`fail_unfinished_tool_execs()`), then marks the scan `FAILED`. The discovery and nmap phase handlers do the same per target.
  - `start_tool_exec()` commits the row when the run starts (it used to be only flushed), so a rollback cannot make it disappear.
  - **Finalisation:** exception paths now set `finished_at`, `duration_ms`, `error_message`, `exit_code`, and keep the `raw_output` / `command_line` the runner had already returned (kept in a plain attribute because a failed flush expires the mapped ones).
  - **Exit codes:** the tool's real code is stored; 124 = timeout, 127 = binary not installed, 1 = internal error. There is still no separate timeout column; the code and the message distinguish it.
  - **Command lines:** runners return the argv they executed and `record_tool_result()` stores it, replacing the hand-written approximations. ZAP is driven over HTTP, so its "command line" lists the API calls.
  - Tests: `backend/tests/test_scan_phases.py` (failed flush inside a phase, runner exception, unfinished executions).

### M5. No tests for runners or parsers

- **Where:** `backend/tests/`
- **Status:** verified
- **What is wrong:**
  - Only `test_service_profile.py` and `test_fingerprint.py` mention these tools.
  - There are no tests for `tools/*`, `parsers/*` or the phase functions.
  - There are no sample outputs for empty, malformed or partial input.
- **Impact:** Nothing would catch the breakages described in H1 and M2.
- **Fix:** Add fixture-based parser tests for each tool, runner tests with a mocked `subprocess.run`, and one phase test that checks the `ToolExecution` and `Vulnerability` linkage.
- **Resolution: fixed** — commits `6b419a4` and `e8a1fb1`. 174 runner, parser and phase tests; 474 backend tests in total after the re-review fixes (`8cc2d2b`), all passing with `-W error`.
  - `backend/tests/test_tool_base.py` (10): `run_command`, `ToolResult`, temp directories.
  - `backend/tests/test_tool_runners.py` (103): every runner with a mocked `subprocess.run` — non-zero exit, timeout, missing binary, empty output, flags, validation, temp-file leaks.
  - `backend/tests/test_tool_parsers.py` (37): nuclei, httpx, katana, nikto, masscan, nmap discovery, NSE, ZAP — valid, empty, malformed and partial input.
  - `backend/tests/test_scan_phases.py` (24): `ToolExecution` / `Vulnerability` / `Port` linkage for nuclei, nikto and discovery, error handlers, progress.
  - Not covered: phase tests for httpx, katana, ssh-audit, NSE, sslscan, testssl and ZAP (their runners and the shared helpers are covered). Fixtures are schema-derived, not captured (see M2).

## Low

### L1. Progress ranges and the docstring do not match the code

- **Where:** `backend/app/tasks/scan_tasks.py:62-72` (docstring) versus `:103-188` and the per-phase `progress` formulas (`:1083`, `:1159`, `:1181`, `:1214`, `:1341`, `:1497`)
- **Status:** verified
- **What is wrong:**
  - The nuclei phase uses `0.9 + 0.1*x` (`:1341`) and sets `1.0` at `:1181` and `:1214`.
  - `nuclei_endpoints` then uses `0.88 + 0.03*x` (`:1497`) and sets `0.91`.
  - nse starts at `0.91`. The ssh-audit phase uses `0.8 + 0.1*x` (`:1159`) and sets `0.9` at `:1083`, but nuclei is announced at `0.85`.
  - The httpx and katana phases use 75-80%, while the docstring says 75-78% and 78-80%.
- **Impact:** The progress bar jumps backwards after nuclei finishes.
- **Fix:** Define the phase ranges in one table and compute progress from it.
- **Resolution: fixed** — commit `e8a1fb1`. `PHASE_PROGRESS` in `tasks/scan_tasks.py` is the only place ranges are defined; phases report through `set_phase_progress()`, which never lowers `scan.progress_percent`. The docstring, the orchestrator's `update_state` values and the table in `docs/scan-lifecycle.md` now agree (nuclei 85–88 %, endpoints 88–91 %, NSE 91–93 %, …). Tests: `TestProgress` in `test_scan_phases.py`.

### L2. nmap runs as root, with a sudoers entry that does nothing useful

- **Where:** `backend/Dockerfile.celery:79-82`; `backend/app/tools/nmap.py`; `backend/app/tools/nmap_nse.py`
- **Status:** verified
- **What is wrong:**
  - The container runs as root (no `USER`), so the sudoers entries for root add nothing.
  - The runner prefixes `sudo` only when `-sS` is present. `nmap_nse.py` and `nmap.py`'s discovery path use `-sT`.
  - The runner calls `settings.NMAP_PATH or 'nmap'`. That resolves through PATH, not through the `/usr/local/bin/nmap` the sudoers entry names.
- **Impact:** The container runs everything, including ZAP/nikto parsing code, as root.
- **Fix:** Run as a non-root user with `cap_net_raw` and `cap_net_admin` on nmap and masscan (via `setcap`) and drop `sudo`.
- **Resolution: fixed in code; deferred-needs-live-scanner-test** — commits `f980045` and `6b419a4`.
  - `sudo` and both sudoers entries are removed from the image; no runner calls `sudo` any more.
  - The worker runs as the unprivileged user `peek` (uid 10001). `backend/docker/celery-entrypoint.sh` starts as root only to give the shared `./data` volume to that user, then drops privileges with `setpriv`. `user: root` is removed from `docker-compose.yml`.
  - `nmap` and `masscan` get `cap_net_raw` through `setcap`; the nmap runner adds `--privileged` for raw-socket scan types when not root. `cap_net_admin` is deliberately **not** set: it is not in Docker's default capability set, and a file capability outside the bounding set makes the binary fail to start.
  - `PEEK_WORKER_RUN_AS_ROOT=1` restores the old behaviour.
  - Risk that needs a live check: the API container still runs as root and creates the SQLite database in the same volume. The entrypoint waits up to 30 s for the database file and changes its owner; this interaction (including WAL files) has not been exercised.

### L3. Image hygiene

- **Where:** `backend/Dockerfile.celery`
- **Status:** verified
- **What is wrong:**
  - `build-essential`, `gcc`, `libssl-dev`, `libssh2-1-dev` and `wget` stay in the final image. A multi-stage build would avoid this.
  - The apt installs lack `--no-install-recommends`, except for the testssl one.
  - `unzip -o` extracts into `/app`, leaving `README.md` and `LICENSE.md` beside the application.
  - amd64 is hard-coded in the zip names, so the image breaks on ARM hosts.
  - nmap's `make install` leaves the build tree in the image only until the `rm -rf`, which is fine, but `.dockerignore` coverage was not fully checked.
- **Fix:** Use a multi-stage build and extract into a temporary directory.
- **Resolution: fixed (not built)** — commit `f980045`. Multi-stage build: compiler, dev headers, `git`, `wget`/`curl` and `unzip` exist only in build stages. All apt installs use `--no-install-recommends`. Zips are unpacked in a build stage, not into `/app`. The architecture comes from `dpkg --print-architecture` with checksums for amd64 and arm64 (other architectures fail the build). `.dockerignore` was checked: it excludes `.venv`, caches and bytecode; `tests/` is copied into the image (harmless, left as is).

### L4. Temporary files and directories can leak

- **Where:** `backend/app/tools/httpx.py` (`mkdtemp`, cleaned up by the caller at `backend/app/tasks/scan_tasks.py:890-894`, only on the success path); `backend/app/tools/katana.py` (`Path(temp_dir).rmdir()` fails silently if the directory is not empty)
- **Status:** verified
- **Impact:** Slow disk growth on long-running workers.
- **Resolution: fixed** — commits `6b419a4` and `e8a1fb1`. All runners use `temp_workdir()`, which removes the whole directory in every case. httpx keeps its directory only while a screenshot is waiting to be copied; the phase calls `output.cleanup()` in a `finally` (the old code only cleaned up on success and referenced `output` before assignment when the runner raised). The nuclei endpoint URL list is removed in a `finally`. `test_tool_runners.py` fails any test that leaves a temp file behind.

### L5. Some timeout semantics are questionable

- **Where:** `backend/app/tools/katana.py:~86`; `backend/app/tools/httpx.py`; `backend/app/tools/nikto.py`
- **Status:** katana point **unverified** (from the agent's recollection of upstream behaviour)
- **What is wrong:**
  - Katana passes `-timeout <overall>` at `tools/katana.py:~86` with the comment "overall timeout". As the agent recalls, katana's `-timeout` is a per-request timeout.
  - The httpx timeout error message says "after {timeout}s" but the real limit is `total_timeout`.
  - Nikto's `-maxtime` and the subprocess timeout of `timeout + 30` are consistent (no issue).
- **Resolution: fixed** — commit `6b419a4`.
  - katana: the reviewer's recollection was right. `-timeout` is per request (v1.8.0 `cmd/katana/main.go`); PEEK now passes `-timeout 10 -crawl-duration <budget>s`.
  - httpx: the timeout error now reports the real subprocess limit.
  - sslscan now honours `global_tool_timeout_seconds`; `testssl_timeout` falls back to 300 s when unset.
  - Not changed: `run_zap_baseline(timeout=…)` only caps the spider wait; ZAP has no single overall timeout.

## Info

- **Structure:** parsers are split between `tools/*` (for example `parse_nmap_xml`, `parse_nuclei_output`, `parse_httpx_output`, and the sslscan and nse parsers) and `parsers/*` (the functions that create DB rows). This is inconsistent across tools but works. Nuclei, httpx, katana, testssl and ssh-audit all have a runner, a parser and phase wiring.
- **Toggles:** `enable_httpx`, `enable_katana`, `enable_nuclei_endpoints`, `enable_sslscan`, `enable_testssl` and `enable_nikto` are read through `getattr` with defaults. The nse phase always runs (`backend/app/tasks/scan_tasks.py:157`). Whether the `ScanConfig` model defines every toggle was not checked.
- **Linkage** looks correct in the nuclei and testssl phases: both set `scan_target_id` and `port_id`, and results carry `tool_execution_id`.
- **Dedup:** the nuclei phase dedups vulnerabilities per target by `template_id`, `port` and `matched_at` before inserting. No issue found.
- **ssh-audit pin** is not part of the bump. It is `ssh-audit==3.9.0` in `backend/requirements.txt`, which is exact and good.
- **`nmap_discovery`** marks a target `FAILED` on a bad run but the scan continues. This looks intentional.
**Resolution (actionable Info items):**

- **Toggles:** the NSE phase now honours `enable_nse` (which exists on `ScanConfig`) and sets `current_phase`; it used to run unconditionally. Fixed in `e8a1fb1`.
- **Structure** (parsers split between `tools/*` and `parsers/*`): **won't fix** here. Moving them is a pure refactor with no behaviour change and would touch every import; the new tests cover both locations.
- **`nmap_discovery` marks a target `FAILED` and the scan continues:** kept as is (intentional). A parse failure now also marks the target failed.
- **Linkage, dedup, ssh-audit pin:** no action needed.

## What was reviewed

- `git show 7b9c488 -- backend/Dockerfile.celery` and the full current Dockerfile.
- `tools/httpx.py`, `katana.py`, `nuclei.py`, `testssl.py`, `nikto.py`, `nmap.py`, `masscan.py` and `ssh_audit.py`, plus parts of `nmap_nse.py`.
- `parsers/nuclei_parser.py` and `parsers/httpx_parser.py`.
- `tasks/scan_tasks.py`: the orchestrator, the discovery, nuclei and testssl phases, and a grep of every phase.
- The tests directory listing.

## What could not be checked

- Real behaviour of nuclei 3.11.1, httpx 1.12.0 and katana 1.8.0 (flags, JSON schema, defaults). Nothing is installed in the review sandbox, and no changelog review was done.
- Whether the build actually succeeds. Dependencies for nmap 7.991 and testssl 3.2.4 were not tested.
- `scheduled_scan_tasks.py`, the Alembic migrations, the `ScanConfig` model, and the zap, sslscan and `nmap_nse` runner internals.
- `.dockerignore` and the compose files in detail.
- The security aspects of the image beyond hygiene (covered by `security-reviewer`; see `2026-10-security-review.md`).

## Top fixes recommended by the agent

1. **H1** — treat non-zero exit and empty output as failure.
2. **M1** — checksums and SHA pins.
3. **M2 + M5** — run the new binaries once and add fixture tests.

## Resolution summary

Fixes are on branch `review/scan-security-2026-10`, commits `2a15257..5fc1564` (reviewed commit: `7b9c488`).

| Finding | Status | Where |
|---|---|---|
| H1 failed run saved as clean scan | fixed | `6b419a4`, `e8a1fb1` — `tools/base.py`, all runners, `tasks/scan_tasks.py` |
| M1 pins not reproducible / verified | fixed (image not built) | `f980045` — `Dockerfile.celery` |
| M2 version jumps unverified | fixed by source review; live run deferred | `6b419a4` — `tools/httpx.py`, `tools/katana.py`, `tools/nikto.py`, `docs/tools/*` |
| M3 no browser for screenshots | fixed (Chromium installed); deferred-needs-live-scanner-test | `f980045`, `6b419a4` |
| M4 phase error handling | fixed | `e8a1fb1` — `tasks/scan_tasks.py` |
| M5 no runner/parser tests | fixed | `6b419a4`, `e8a1fb1` — `backend/tests/` |
| L1 progress goes backwards | fixed | `e8a1fb1` |
| L2 root + useless sudoers | fixed in code; deferred-needs-live-scanner-test | `f980045`, `6b419a4` |
| L3 image hygiene | fixed (image not built) | `f980045` |
| L4 temp files leak | fixed | `6b419a4`, `e8a1fb1` |
| L5 timeout semantics | fixed | `6b419a4` |
| Info: NSE toggle ignored | fixed | `e8a1fb1` |
| Info: parser layout | won't fix (refactor only) | — |

## Re-review (2026-10-10)

The `scan-tool-reviewer` agent re-reviewed `381f8b0..5fc1564` read-only, ran the test suite and checked flags against the unpacked upstream sources. **Verdict: OK with notes** — no Critical or High findings; H1, M3, M4 (with edge gaps), M5 and L1–L5 judged fixed, M1 fixed in structure (pinned values not independently verifiable offline), M2 partial (no captured real-output fixtures; nikto's `-maxtime`/`-nointeractive` not re-checked by the agent).

| Re-review finding | Severity | Resolution |
|---|---|---|
| N1 raw-socket detection matches exact flags only (`-A`, `-sSV`, `-PS`) | Low | **fixed** in `8cc2d2b` — `-A` added; `nmap_args` is now an allow-list, so combined or unknown flags are rejected with a clear validation error instead of failing inside nmap |
| N2 `command_line` stays a placeholder (or empty) when validation fails or an exception occurs before the run | Low | **won't fix** — in those cases no command was executed; the error message says why |
| N3 ZAP returns success together with a warning in `error_message` (unfinished spider) | Low | **won't fix** — intended: partial coverage must be visible. Nothing in the backend or frontend treats `ToolExecution.error_message` alone as failure (checked) |
| N4 30 s wait for the SQLite file on a fresh install; KEV cache not writable on the dev bind mount | Low | **deferred-needs-live-scanner-test** — on the checklist below |
| N5 `.dockerignore` did not exclude `.env` | Info | **fixed** in `8cc2d2b` |
| N6 a timeout kills only the direct child process (testssl/Chromium children may linger); 64 MB `/dev/shm` for Chromium | Low | **open** — not changed; needs process-group handling in `run_command()` and a live check |
| N7 masscan comment, cached tag validation, `cap_drop` breaks nmap, hard-coded `nikto` path | Info | comment **fixed** in `8cc2d2b`; `cap_drop` is documented; the rest left as is |

## Live verification checklist

Nothing below could be checked in the fix environment: Docker is not available there and no scanner binary was executed. Run it with the real image against a hellbox target (`scripts/qa/hellbox-qa.prompt`, target built by `scripts/qa/setup-hellbox-v3.sh`).

**Image build**

- [ ] `docker compose build celery` succeeds on amd64 (and arm64 if used): digest pull, every `sha256sum -c`, the three commit-pin checks, the nmap source build with `DESTDIR`, the `libssh2` runtime package lookup.
- [ ] The build-time smoke test passes: binaries start as user `peek`, `getcap` shows `cap_net_raw` on nmap and masscan, `perl -MXML::Writer …` loads, `nuclei -tl -duc -tags cve` lists more than 100 templates from the pinned set.
- [ ] `docker compose build --build-arg INSTALL_CHROMIUM=false celery` also builds.

**Non-root worker**

- [ ] Worker and beat start; `docker compose exec celery id` shows uid 10001 (`peek`).
- [ ] Fresh install (empty `./data`): the backend creates `peek.db`, the worker can write to it, and a scan runs end to end. Repeat on an existing deployment whose `./data` is root-owned.
- [ ] After a backend restart the worker can still write (SQLite `-wal`/`-shm` ownership).
- [ ] `celery beat` writes `/app/data/celerybeat-schedule` and scheduled scans fire.
- [ ] A config with `-sS` in `nmap_args` (the schema default) works as non-root via `--privileged` + `cap_net_raw`. Also try `-O` and a UDP NSE profile, which may want `cap_net_admin`.
- [ ] `PEEK_WORKER_RUN_AS_ROOT=1` still works, including nuclei finding its templates.

**Scanners against hellbox**

- [ ] nuclei 3.11.1: findings appear for the hellbox CVEs; `ToolExecution.command_line` is the real command; no template download happens at scan time (run with egress blocked or watch the log); the `.nuclei-ignore` copied from the pinned template repo is honoured (no `dos`/`fuzz` templates run).
- [ ] Failure path: temporarily break a run (e.g. `NUCLEI_PATH=/bin/false`, or stop the target mid-scan) and confirm the `ToolExecution` has a non-zero `exit_code` and an `error_message`, and that no "0 findings" result is shown as clean.
- [ ] httpx 1.12.0: `HttpxResult` has status, title, technologies, `tls_version`/`tls_cipher` (from `-tls-grab`), `jarm_hash`, `redirect_chain`, CDN/WAF fields. Confirm no requests go to certificate SAN hosts.
- [ ] httpx screenshots: enable `httpx_screenshots`; a PNG is stored and served by `GET /api/scans/{id}/screenshots/{port_id}`; Chromium starts as non-root with `--no-sandbox`; `-st 10s` is accepted; `/tmp` has no leftover `httpx_*` or Chromium profile directories.
- [ ] katana 1.8.0: endpoints are stored; the crawl stops at `-crawl-duration`; `content_type` is filled from the response headers; check the size of the stored JSONL with `-omit-raw -omit-body`.
- [ ] nikto 2.6.1: starts (XML::Writer present), the JSON report is a list of host records, and findings are stored as individual vulnerabilities. Check what Nikto does for a port with no web server (exit code and report content).
- [ ] nmap 7.991: discovery, service detection and NSE XML parse as before; a filtered host hits `--host-timeout` and is handled sensibly.
- [ ] testssl.sh 3.2.4: runs with the installed `bsdextrautils`/`bind9-dnsutils`; a non-TLS port yields a `FATAL` record and a failed execution; note the exit codes seen on hellbox.
- [ ] sslscan, ssh-audit, masscan (legacy) and ZAP: one successful and one failing run each.
- [ ] Capture one real output per tool from these runs and replace the schema-derived samples in `backend/tests/test_tool_parsers.py`.

**Pipeline**

- [ ] A stored config with a now-disallowed `nmap_args` entry fails the nmap run with a readable validation error; configs with only allowed flags are unaffected.
- [ ] `nuclei_templates` set to a relative path (e.g. `http/cves/2024`) resolves inside the pinned template set and runs.
- [ ] After a tool timeout no scanner or Chromium child processes are left running in the worker (`ps` inside the container).
- [ ] The progress bar only moves forward across all 12 phases, including with katana + nuclei endpoints enabled.
- [ ] With `enable_nse=false` the NSE phase is skipped.
- [ ] Kill the worker mid-scan: the scan ends `FAILED`/cancelled and no `ToolExecution` is left without `finished_at`.
