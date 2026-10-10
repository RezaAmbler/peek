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

### M2. The environment does not match the pin, so the 5.x behaviour the commit relies on was not exercised

- **Where:** `backend/requirements.txt:8`
- **Status:** verified for the mismatch. The 5.x behaviour is unverified.
- **What is wrong:** The interpreter has bcrypt 4.2.0 installed, but the code and tests assume 5.0.0. `pytest` is not installed, so `test_security.py` could not be run.
- **Impact:** The claims "5.x raises on >72 bytes" and "malformed returns False" were not checked against the pinned version.
- **Fix:** Run the tests in the real image or venv (`pip install -r backend/requirements.txt`). Add a small test asserting `bcrypt.__version__`, or at least the behaviours that matter.

## Low

### L1. Passwords with a NUL byte: behaviour is unverified on 5.x

- **Where:** `backend/app/core/security.py:13-14`
- **Status:** unverified
- **What is wrong:** On 4.2.0, `hashpw(b"a\x00b")` did not raise. It was not checked whether it silently truncates at the NUL byte, which would make `a\x00b` and `a` equivalent. The agent's understanding is that bcrypt 5 may raise `ValueError` on NUL bytes. If it does, `get_password_hash` would 500 in user creation and password reset. `verify_password` would also 500 on login with a NUL-containing password, because the `_encode` call is outside the `try`. Wherever `_encode` and `checkpw` run, a NUL in the password could produce a 500.
- **Scenario:** A `POST /login` with `password=a%00b` yields a 500 instead of a 401. This is unauthenticated and only a nuisance, but it is also an error-oracle.
- **Fix:** Wrap `_encode` inside the `try` in `verify_password`. Reject or handle `\x00` in `validate_password_strength`.

### L2. Truncation can split a multibyte UTF-8 character

- **Where:** `backend/app/core/security.py:14`; `backend/app/schemas/user.py:61`, `:82`
- **Status:** verified by reading the code
- **What is wrong:** `[:72]` can cut mid-codepoint. This matches passlib, so it is compatible and not a regression. It is still worth noting that the passphrase effectively has only 72 bytes of entropy.
- **Impact:** The schema allows `max_length=100` characters (`backend/app/schemas/user.py:61,82`), and non-ASCII characters can be up to 4 bytes each, so most of a long password may be ignored without the user knowing.
- **Fix (optional):** Pre-hash with SHA-256 plus base64. That would break existing hashes unless versioned, so the agent recommends not doing it now.

### L3. No rehash or upgrade path and a fixed cost factor

- **Where:** `backend/app/core/security.py:26`
- **Status:** verified
- **What is wrong:** `bcrypt.gensalt()` uses the default of 12 rounds and is not configurable. Passlib's `deprecated="auto"` and `needs_update` were not actually used by callers, so nothing functional is lost.
- **Impact:** There is no way to raise the cost later without code changes, and no on-login rehash.
- **Fix:** Add a `BCRYPT_ROUNDS` setting and rehash on a successful login if the stored cost is below it.

### L4. Seeded default `admin`/`admin` credential

- **Where:** `backend/app/main.py:160`; also documented in the login docstring at `backend/app/routers/auth.py:56`
- **Status:** verified, out of scope for this commit
- **What is wrong:** Pre-existing and not changed by this commit. It is already tracked in `docs/soc-roadmap.md`.

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
