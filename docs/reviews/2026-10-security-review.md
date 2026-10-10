# Security Review — 2026-10

- **Agent:** `security-reviewer` (Claude Code project subagent)
- **Date:** 2026-10-10
- **Commit reviewed:** `7b9c488` (fix(backend): use bcrypt directly, drop passlib; dispose test engines; bump scanners)
- **Branch:** `review/scan-security-2026-10`
- **Scope:** the bcrypt/passlib change in `backend/app/core/security.py`, `backend/requirements.txt`, and the security tests (`backend/tests/test_security.py`)
- **Verdict:** OK with notes
- **Mode:** read-only review; no code was modified

> Findings below are the agent's report, lightly reformatted. **Important caveat:** the review sandbox had bcrypt **4.2.0** installed, not the pinned **5.0.0**, and `pytest` was not installed. Runtime checks were made against 4.2.0 only; `test_security.py` was **not run**. Behaviour on bcrypt 5.0.0 is unverified throughout.

## Severity summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 2 |
| Low | 4 |
| Info | 6 |

## Critical

None.

## High

None.

## Medium

### M1. A truncated stored hash can raise `PanicException` instead of returning False (a 500 on login)

- **Where:** `backend/app/core/security.py:17-22`
- **Status:** verified on installed bcrypt 4.2.0. **Unverified on 5.0.0**, the pinned version, which could not be installed. The agent would not assume it is fixed there.
- **What is wrong:** `verify_password` only catches `ValueError`. Running `bcrypt.checkpw(b"a", b"$2b$12$xxxxxxxxxx")` against the installed bcrypt produced `pyo3_runtime.PanicException` ("range end index 22 out of range"). That exception derives from `BaseException`, so `except ValueError` does not catch it. An empty string raised `ValueError` and was handled correctly. The commit message and test claim "malformed hash -> False", but the test only uses `"not-a-bcrypt-hash"`, which takes the `ValueError` path.
- **Scenario:** A user row with a hash that starts correctly but is truncated (a bad migration or manual DB edit) turns that user's login into an unhandled 500. An attacker who can submit that username could use it to tell which accounts are corrupted. Passlib's `verify` would have raised `ValueError` for malformed hashes and did not hit this path.
- **Fix (in order of the agent's preference):**
  - Validate the stored hash with a regex first, `^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$`, and return False if it doesn't match (described by the agent as the simpler option).
  - Alternatively, catch `Exception` plus `pyo3_runtime.PanicException` explicitly.
  - Add a test with a truncated `$2b$12$...` hash.

  _Note: the agent's report also included an inline snippet, `except (ValueError, BaseException-subclass PanicException)...`, which is shorthand rather than valid Python; the two options above are what it describes._
- **Resolution: fixed** — commit `d94c0b5`, `backend/app/core/security.py`.
  - What bcrypt 5.0.0 actually does (run in the project venv): `checkpw(b"a", b"$2b$12$xxxxxxxxxx")` raises `ValueError: Invalid salt`. The `PanicException` seen on 4.2.0 does not occur on the pinned version, so there was no 500 on 5.0.0. The code no longer depends on that.
  - `verify_password` checks the stored value against the bcrypt hash shape first (both of the reviewer's options are implemented), catches every `Exception` from bcrypt, and also treats a pyo3 `PanicException` as a mismatch while letting other `BaseException`s through. A `None`, non-string or bytes hash returns False.
  - Tests: `TestPasswordHashing.test_unusable_stored_hash_never_raises` (14 malformed variants, including the truncated `$2b$12$…` case), `test_bcrypt_panic_is_swallowed_but_other_base_exceptions_propagate`, and end to end `test_corrupt_stored_hash_is_401_not_500` in `backend/tests/test_auth_login.py`.

### M2. The environment does not match the pin, so the 5.x behaviour the commit relies on was not exercised

- **Where:** `backend/requirements.txt:8`
- **Status:** verified for the mismatch. The 5.x behaviour is unverified.
- **What is wrong:** The interpreter has bcrypt 4.2.0 installed, but the code and tests assume 5.0.0. `pytest` is not installed, so `test_security.py` could not be run.
- **Impact:** The claims "5.x raises on >72 bytes" and "malformed returns False" were not checked against the pinned version.
- **Fix:** Run the tests in the real image or venv (`pip install -r backend/requirements.txt`). Add a small test asserting `bcrypt.__version__`, or at least the behaviours that matter.
- **Resolution: fixed** — commit `d94c0b5` (tests), setup done in `backend/.venv`.
  - The venv has `backend/requirements.txt` installed, so the suite runs against bcrypt **5.0.0**. `TestPinnedBcrypt.test_installed_version_matches_the_pin` fails if the installed bcrypt differs from the pin.
  - The 5.x behaviours the code relies on are asserted directly: input over 72 bytes raises `ValueError`; malformed and truncated hashes raise `ValueError`; `$2a$` and `$2y$` hashes verify.
  - One reviewer assumption was wrong on 5.0.0: `$2x$` hashes **are** accepted by bcrypt (they verify). This has no security impact; such hashes are upgraded to `$2b$` on the next login.
  - `backend/tests/conftest.py` supplies a test-only `SECRET_KEY` when the environment provides one shorter than the 32 characters `core/config.py` requires (for example `SECRET_KEY=test-secret`). The production validator is unchanged.

## Low

### L1. Passwords with a NUL byte: behaviour is unverified on 5.x

- **Where:** `backend/app/core/security.py:13-14`
- **Status:** unverified
- **What is wrong:** On 4.2.0, `hashpw(b"a\x00b")` did not raise. It was not checked whether it silently truncates at the NUL byte, which would make `a\x00b` and `a` equivalent. The agent's understanding is that bcrypt 5 may raise `ValueError` on NUL bytes. If it does, `get_password_hash` would 500 in user creation and password reset. `verify_password` would also 500 on login with a NUL-containing password, because the `_encode` call is outside the `try`. Wherever `_encode` and `checkpw` run, a NUL in the password could produce a 500.
- **Scenario:** A `POST /login` with `password=a%00b` yields a 500 instead of a 401. This is unauthenticated and only a nuisance, but it is also an error-oracle.
- **Fix:** Wrap `_encode` inside the `try` in `verify_password`. Reject or handle `\x00` in `validate_password_strength`.
- **Resolution: fixed** — commit `d94c0b5`.
  - Measured on 5.0.0: `hashpw(b"a\x00b")` does not raise and does **not** truncate at the NUL (`a`, `a\x00b` and `a\x00c` are three different passwords). So neither the 500 nor the equivalence existed on the pinned version.
  - Hardening anyway: encoding now happens inside the `try` in `verify_password`, and `validate_password_strength` rejects NUL characters in new and reset passwords.
  - Tests: `TestNulBytes`; `test_bad_credentials_are_uniform_401` sends NUL-containing passwords through the login handler and gets a 401.

### L2. Truncation can split a multibyte UTF-8 character

- **Where:** `backend/app/core/security.py:14`; `backend/app/schemas/user.py:61`, `:82`
- **Status:** verified by reading the code
- **What is wrong:** `[:72]` can cut mid-codepoint. This matches passlib, so it is compatible and not a regression. It is still worth noting that the passphrase effectively has only 72 bytes of entropy.
- **Impact:** The schema allows `max_length=100` characters (`backend/app/schemas/user.py:61,82`), and non-ASCII characters can be up to 4 bytes each, so most of a long password may be ignored without the user knowing.
- **Fix (optional):** Pre-hash with SHA-256 plus base64. That would break existing hashes unless versioned, so the agent recommends not doing it now.
- **Resolution: fixed** — commit `d94c0b5`.
  - New and reset passwords longer than 72 bytes (UTF-8) are rejected by `validate_password_strength` (`backend/app/schemas/user.py`), so nothing is silently ignored any more.
  - `_encode` truncates on a character boundary. Hashes written with the old byte-exact truncation still verify: `verify_password` also tries the legacy encoding when the two differ (only for passwords over 72 bytes whose cut lands inside a character).
  - Pre-hashing with SHA-256 was not done, as the reviewer recommended.
  - Tests: `TestTruncation`. Documented in the README ("Password Storage").

### L3. No rehash or upgrade path and a fixed cost factor

- **Where:** `backend/app/core/security.py:26`
- **Status:** verified
- **What is wrong:** `bcrypt.gensalt()` uses the default of 12 rounds and is not configurable. Passlib's `deprecated="auto"` and `needs_update` were not actually used by callers, so nothing functional is lost.
- **Impact:** There is no way to raise the cost later without code changes, and no on-login rehash.
- **Fix:** Add a `BCRYPT_ROUNDS` setting and rehash on a successful login if the stored cost is below it.
- **Resolution: fixed** — commit `d94c0b5`. `BCRYPT_ROUNDS` setting (default 12, validated to 4–31). `password_needs_rehash()` is true when the stored cost differs or the hash is not `$2b$`; the login handler then re-hashes after a successful login. A failure to re-hash is logged and never fails the login. Tests: `TestRehash`, `test_hash_is_upgraded_on_login_when_cost_differs`, `test_rehash_failure_does_not_fail_the_login`.

### L4. Seeded default `admin`/`admin` credential

- **Where:** `backend/app/main.py:160`; also documented in the login docstring at `backend/app/routers/auth.py:56`
- **Status:** verified, out of scope for this commit
- **What is wrong:** Pre-existing and not changed by this commit. It is already tracked in `docs/soc-roadmap.md`.
- **Resolution: fixed** — commit `d94c0b5`, `backend/app/main.py` (`create_default_admin`, `resolve_initial_admin_password`).
  - PEEK no longer seeds `admin`/`admin`. When no `admin` user exists, the password comes from `INITIAL_ADMIN_PASSWORD`. It must pass the password policy; a weak value stops startup rather than creating a weak account.
  - If the variable is unset, a random password (`secrets.token_urlsafe(18)`) is generated and printed once to the backend log. This keeps `docker compose up` working without extra configuration. A configured password is never logged.
  - **Existing deployments are not affected:** an existing `admin` row is never modified. If it still verifies against the old default `admin`, a `SECURITY` warning is printed on every start.
  - A forced password change at first login (`must_change_password`, as sketched in `docs/soc-roadmap.md`) was **not** implemented: it needs a schema migration and a frontend flow. The variable is named `INITIAL_ADMIN_PASSWORD`; the roadmap's working name was `ADMIN_BOOTSTRAP_PASSWORD`.
  - Documented in `README.md` ("Initial Admin Account"), `SECURITY.md`, `backend/.env.example`; the QA prompts under `scripts/qa/` no longer assume `admin`/`admin`.
  - Tests: the admin-seeding tests in `backend/tests/test_auth_login.py`.

## Info

- **Legacy hash compatibility is fine.**
  - `$2a$` and `$2y$` prefixes verified on the installed bcrypt.
  - Passlib 1.7.4 with bcrypt 4.3.0 wrote `$2b$` hashes.
  - Passlib's 72-byte truncation matches `_encode`.
  - The legacy-hash tests are hard-coded, which is good.
  - `$2x$` is not accepted by bcrypt and falls through to `ValueError`, giving False.
- **`None` stored hash.** `hashed_password` is `nullable=False` (`backend/app/models/user.py:13`), so `None` is not expected. If it did occur, `.encode` would raise `AttributeError` and cause a 500.
- **Empty hash.** Verified to return False via `ValueError`.
- **Login timing.**
  - `backend/app/routers/auth.py:72-73` always runs `verify_password`, using a dummy `$2b$12$` hash for unknown users.
  - The dummy hash is well-formed. It took about 0.29s in the sandbox, which is full cost, so there is no fast-fail leak.
  - `checkpw` compares in constant time.
  - The remaining difference is that the `is_active` check comes after the password check. This is acceptable, but it does reveal "inactive" with a correct password.
  - Malformed stored hashes (see M1) are the one case that breaks timing parity and error uniformity.
- **Pin.**
  - `bcrypt==5.0.0` is exact.
  - passlib was removed from `backend/requirements.txt`. The grep found no remaining `passlib` or `CryptContext` imports in code. Mentions remain only in tests, comments and docs.
  - Both Dockerfiles use `backend/requirements.txt`. No other requirements or lock files containing bcrypt were found.
  - Advisories for bcrypt 5.0.0 could not be checked offline (unverified).
- **JWT.**
  - Jose decode pins `algorithms=[settings.ALGORITHM]`, and `exp` is validated by default.
  - `SECRET_KEY` defaults to empty. A validator in `backend/app/core/config.py` rejects weak or placeholder values and keys shorter than 32 characters.
  - `ALGORITHM` is configurable via env. A value of `none` or an unusual algorithm would be a misconfiguration risk, and the code does not allow-list it (rated Low by the agent, unverified).
  - The 7-day access-token lifetime with no refresh or revocation is noted in the roadmap.
  - `datetime.utcnow()` is deprecated but works with jose.
- **Test gaps (`backend/tests/test_security.py`).**
  - Covered: round trip, wrong password, legacy hashes, unicode, long password, a non-bcrypt string, forged and expired JWTs.
  - Missing:
    - truncated `$2b$` hash (M1)
    - empty string hash
    - NUL byte in the password
    - `$2a$` and `$2y$` legacy variants
    - a multibyte character straddling byte 72
    - an end-to-end login test for a corrupt hash
  - The "dummy hash" test does not show the dummy is a valid hash. It only asserts False, which a malformed hash would also give.
**Resolution (actionable Info items):**

- **`None` stored hash:** `verify_password` returns False for `None` and other non-string values instead of raising. Fixed in `d94c0b5`.
- **JWT `ALGORITHM`:** now allow-listed to `HS256`/`HS384`/`HS512` in `core/config.py`; `none` or an asymmetric algorithm stops startup. Fixed in `d94c0b5`.
- **`datetime.utcnow()` deprecation:** replaced by `core.timeutil.utcnow()` across the backend (`2a15257`), which is what lets the suite pass with `-W error`.
- **Test gaps:** all listed cases are now covered — truncated `$2b$` hash, empty hash, NUL byte, `$2a$`/`$2y$`, a multibyte character straddling byte 72, an end-to-end login with a corrupt hash, and the dummy-hash test now proves the hash is well formed and reaches `bcrypt.checkpw`.
- **Login timing (`is_active` checked after the password):** **won't fix**. A 403 for an inactive account is only returned with the correct password, which the reviewer rated acceptable; changing it would make a disabled account indistinguishable from a wrong password for its legitimate owner.
- **7-day access tokens, no refresh or revocation:** **won't fix here**; tracked in `docs/soc-roadmap.md`.
- **Advisories for bcrypt 5.0.0:** not checked (`pip-audit` was not run in this change).
- **Legacy hash compatibility, pin, empty hash:** no action needed.

## What was reviewed

- `git show 7b9c488` for `security.py` and `requirements.txt`, plus the `--stat`.
- Full `backend/app/core/security.py`, `backend/requirements.txt` and `backend/tests/test_security.py`.
- `backend/app/routers/auth.py`, `backend/app/routers/users.py` (create and reset), the password schemas, `backend/app/main.py` (admin seeding) and the `SECRET_KEY` settings in `backend/app/core/config.py`.
- A repo-wide grep for `passlib`, `CryptContext` and the hash and verify helpers.
- Read-only runs against the installed bcrypt 4.2.0.

## What could not be checked

- Behaviour on bcrypt 5.0.0 (the pinned version is not installed).
- Running pytest (not installed).
- Advisories for bcrypt 5.0.0.
- The built Docker image contents.
- The Alembic migrations (not examined in depth). The grep found no hashing in them.

## Top fixes recommended by the agent

1. **M1** — fix before relying on the "malformed hash gives False" guarantee.
2. **M2** — run the security tests under bcrypt 5.0.0.

## Resolution summary

Fixes are on branch `review/scan-security-2026-10`, commit `d94c0b5` (plus `2a15257` for the deprecation cleanup). All behaviour claims below were checked against bcrypt 5.0.0 in `backend/.venv`.

| Finding | Status | Where |
|---|---|---|
| M1 truncated hash → exception | fixed | `d94c0b5` — `core/security.py` |
| M2 environment did not match the pin | fixed | `d94c0b5` — venv on bcrypt 5.0.0, `TestPinnedBcrypt` |
| L1 NUL bytes | fixed | `d94c0b5` — `core/security.py`, `schemas/user.py` |
| L2 truncation splits a character | fixed | `d94c0b5` — `core/security.py`, `schemas/user.py` |
| L3 fixed cost, no rehash | fixed | `d94c0b5` — `core/config.py`, `routers/auth.py` |
| L4 seeded `admin`/`admin` | fixed (forced change at first login not implemented) | `d94c0b5` — `main.py` |
| Info: `None` hash, JWT algorithm allow-list, test gaps, `utcnow` | fixed | `d94c0b5`, `2a15257` |
| Info: `is_active` ordering | won't fix (acceptable per review) | — |
| Info: token lifetime / revocation | won't fix here (roadmap) | — |

## Re-review (2026-10-10)

The `security-reviewer` agent re-reviewed `381f8b0..5fc1564` read-only and probed bcrypt 5.0.0 directly. **Verdict: NEEDS WORK** — the password and auth rework was judged sound (M1, M2, L1, L2, L3 fixed; L4 fixed for new installs and deliberately untouched for existing ones), but it raised one High in the runner area and one Medium. Both are fixed in `8cc2d2b`; the agent has not re-reviewed that commit.

| Re-review finding | Severity | Resolution |
|---|---|---|
| N2 config-derived arguments reach argv unvalidated: `nmap_args` allowed `-oN`/`-iL`/`--script=<path>`/`--datadir` (file write, file read, Lua execution as the worker user) for any authenticated user; `nuclei_templates` accepted any local path or URL; NSE script names could be paths. Pre-existing, not introduced by these changes | High | **fixed** in `8cc2d2b` — `validate_nmap_args` allow-list in `core/validators.py`, enforced in `ScanConfigCreate`, `ScanConfigUpdate` and again in `run_nmap` (covers configs already stored); `nuclei_templates` restricted to paths inside the installed template directory (resolved, symlink-safe) in schema and runner; NSE script names may no longer contain `/` or `.` |
| N1 the generated admin password is written with `print()` to a block-buffered stdout and may not appear in `docker compose logs` | Medium | **fixed** in `8cc2d2b` — `flush=True` on those messages and `PYTHONUNBUFFERED=1` in both images; docs say the log is sensitive until the password is changed. **deferred-needs-live-scanner-test** for the behaviour inside Docker |
| N3 rehash-on-login could overwrite a concurrent password reset; lowering `BCRYPT_ROUNDS` downgraded hashes | Low | **fixed** in `8cc2d2b` — compare-and-set `UPDATE … WHERE hashed_password = <verified hash>`; re-hash only when the stored cost is *below* the setting. The 4–31 range is kept (the test suite uses 4) |
| N4 dummy hash had a fixed cost of 12; a corrupt stored hash returned without bcrypt work | Low | **fixed** in `8cc2d2b` — the dummy hash is generated at import with `BCRYPT_ROUNDS`; a user with an unusable hash is verified against it |
| N5 scanner subprocesses (and Chromium) inherited `SECRET_KEY` etc.; `.env` not in `.dockerignore` | Low | **fixed** in `8cc2d2b` — `scanner_environment()` strips secrets from the child environment; `.env*` excluded from the build context. The worker container itself still receives `backend/.env` (it needs `SECRET_KEY` to import the app) |
| N6 nuclei endpoint list built from crawler output with a substring host match and no newline check | Low | **fixed** in `8cc2d2b` — only `http(s)` URLs without whitespace/control characters whose host equals a scan target are scanned |
| N7 `chown -R` of `./data` changes ownership on a dev bind mount; dev compose mounts `./backend` over the image | Info | **won't fix** — documented; `PEEK_WORKER_RUN_AS_ROOT=1` avoids the ownership change |

Not assessed by the agent, and not changed: the stdlib `xml.etree` parsers used on nmap/sslscan output.

## Live verification checklist

These need a running deployment (Docker was not available in the fix environment). The scanner-side checklist is in `2026-10-scan-tool-review.md`.

- [ ] Fresh install with `INITIAL_ADMIN_PASSWORD` set: login works with it; the password does not appear in `docker compose logs backend`.
- [ ] Fresh install without it: the generated password appears exactly once in the backend log and works; it is not printed again after a restart.
- [ ] A weak `INITIAL_ADMIN_PASSWORD` (for example `admin`) stops the backend with a clear message and creates no account.
- [ ] Upgrade of an existing deployment seeded with `admin`/`admin`: login still works, the `SECURITY` warning is logged on every start, and it disappears after the password is changed.
- [ ] Existing users with cost-12 hashes log in unchanged; after setting `BCRYPT_ROUNDS=13` their hash is upgraded on the next login (check the `$2b$13$` prefix in the database).
- [ ] Corrupt a test user's `hashed_password` in the database: login returns 401, not 500.
- [ ] Through the real HTTP stack, `POST /api/auth/login` with `password=a%00b` returns 401 (the handler was tested directly, not through uvicorn/form parsing).
- [ ] As a non-admin user, `PATCH /api/configs/{id}` with `nmap_args: ["-sV","-oN","/app/data/x"]` or `nuclei_templates: "/etc/passwd"` returns 422.
- [ ] Inside the worker, a scanner child process has no `SECRET_KEY` in `/proc/<pid>/environ`.
- [ ] The hellbox QA flow (`scripts/qa/hellbox-qa.prompt`) logs in with the new credential source.
