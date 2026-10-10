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

### M3. Screenshots and headless crawling cannot work in this image

- **Where:** `backend/Dockerfile.celery` (no chromium installed; grep for `chrom` finds nothing); `backend/app/tools/httpx.py:~104-108` (`-ss`); `backend/app/tasks/scan_tasks.py:1004`
- **Status:** verified (no browser installed); consequence unverified
- **What is wrong:**
  - httpx `-ss` and katana `-headless` need a Chromium-class browser.
  - The scan phase hard-codes `headless=False` for katana (`scan_tasks.py:1004`), so only the httpx screenshots option is affected.
- **Impact:** Opting in to screenshots produces failed `ToolExecution` rows.
- **Fix:** Install chromium, or hide the option in the UI and API.

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

### M5. No tests for runners or parsers

- **Where:** `backend/tests/`
- **Status:** verified
- **What is wrong:**
  - Only `test_service_profile.py` and `test_fingerprint.py` mention these tools.
  - There are no tests for `tools/*`, `parsers/*` or the phase functions.
  - There are no sample outputs for empty, malformed or partial input.
- **Impact:** Nothing would catch the breakages described in H1 and M2.
- **Fix:** Add fixture-based parser tests for each tool, runner tests with a mocked `subprocess.run`, and one phase test that checks the `ToolExecution` and `Vulnerability` linkage.

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

### L2. nmap runs as root, with a sudoers entry that does nothing useful

- **Where:** `backend/Dockerfile.celery:79-82`; `backend/app/tools/nmap.py`; `backend/app/tools/nmap_nse.py`
- **Status:** verified
- **What is wrong:**
  - The container runs as root (no `USER`), so the sudoers entries for root add nothing.
  - The runner prefixes `sudo` only when `-sS` is present. `nmap_nse.py` and `nmap.py`'s discovery path use `-sT`.
  - The runner calls `settings.NMAP_PATH or 'nmap'`. That resolves through PATH, not through the `/usr/local/bin/nmap` the sudoers entry names.
- **Impact:** The container runs everything, including ZAP/nikto parsing code, as root.
- **Fix:** Run as a non-root user with `cap_net_raw` and `cap_net_admin` on nmap and masscan (via `setcap`) and drop `sudo`.

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

### L4. Temporary files and directories can leak

- **Where:** `backend/app/tools/httpx.py` (`mkdtemp`, cleaned up by the caller at `backend/app/tasks/scan_tasks.py:890-894`, only on the success path); `backend/app/tools/katana.py` (`Path(temp_dir).rmdir()` fails silently if the directory is not empty)
- **Status:** verified
- **Impact:** Slow disk growth on long-running workers.

### L5. Some timeout semantics are questionable

- **Where:** `backend/app/tools/katana.py:~86`; `backend/app/tools/httpx.py`; `backend/app/tools/nikto.py`
- **Status:** katana point **unverified** (from the agent's recollection of upstream behaviour)
- **What is wrong:**
  - Katana passes `-timeout <overall>` at `tools/katana.py:~86` with the comment "overall timeout". As the agent recalls, katana's `-timeout` is a per-request timeout.
  - The httpx timeout error message says "after {timeout}s" but the real limit is `total_timeout`.
  - Nikto's `-maxtime` and the subprocess timeout of `timeout + 30` are consistent (no issue).

## Info

- **Structure:** parsers are split between `tools/*` (for example `parse_nmap_xml`, `parse_nuclei_output`, `parse_httpx_output`, and the sslscan and nse parsers) and `parsers/*` (the functions that create DB rows). This is inconsistent across tools but works. Nuclei, httpx, katana, testssl and ssh-audit all have a runner, a parser and phase wiring.
- **Toggles:** `enable_httpx`, `enable_katana`, `enable_nuclei_endpoints`, `enable_sslscan`, `enable_testssl` and `enable_nikto` are read through `getattr` with defaults. The nse phase always runs (`backend/app/tasks/scan_tasks.py:157`). Whether the `ScanConfig` model defines every toggle was not checked.
- **Linkage** looks correct in the nuclei and testssl phases: both set `scan_target_id` and `port_id`, and results carry `tool_execution_id`.
- **Dedup:** the nuclei phase dedups vulnerabilities per target by `template_id`, `port` and `matched_at` before inserting. No issue found.
- **ssh-audit pin** is not part of the bump. It is `ssh-audit==3.9.0` in `backend/requirements.txt`, which is exact and good.
- **`nmap_discovery`** marks a target `FAILED` on a bad run but the scan continues. This looks intentional.

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
