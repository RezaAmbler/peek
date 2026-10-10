# Security Policy

We take the security of PEEK seriously. This document describes how to report security issues and what to expect after a report is filed.

## Supported Versions

PEEK is an actively-developed single-branch project. Only the latest commit on `main` is supported for security fixes.

| Version | Supported |
|---------|-----------|
| `main`  | ✅ |
| Any tagged or branch release older than `main` | ❌ |

If you are running an older build, please update to the latest `main` before reporting a vulnerability — the issue may already be fixed.

## Reporting a Vulnerability

**Please do not file public GitHub issues for security vulnerabilities.**

Use one of the following private channels:

1. **GitHub Security Advisories** (preferred): https://github.com/RezaAmbler/peek/security/advisories/new
2. **Email**: reza.ambler@gmail.com — include "PEEK Security" in the subject line.

Include in your report:

- A description of the vulnerability and its impact.
- Steps to reproduce, including PEEK version (commit SHA), environment details, and any required configuration.
- Proof-of-concept code or screenshots, if available.
- Whether you intend to disclose publicly, and on what timeline.

## What to Expect

| Stage | Target turnaround |
|---|---|
| Acknowledgement of receipt | within 3 business days |
| Initial assessment & severity rating | within 7 business days |
| Fix or mitigation plan | within 30 days of acknowledgement |
| Coordinated disclosure | within 90 days of initial report |

We follow a **90-day coordinated-disclosure window** by default. If a fix is unlikely within that window, we will coordinate with the reporter on an extension.

After a fix lands on `main`, we publish a GitHub Security Advisory with credit to the reporter (unless anonymity is requested).

## Scope

In scope:

- The PEEK backend (FastAPI app, Celery worker, scheduled-scan code)
- The PEEK frontend (React/Vite UI)
- The default Docker images and `docker-compose.yml` published in this repo
- The deployment scripts under `deploy/`

Out of scope (please do not report):

- Vulnerabilities in third-party scanner tools (nmap, nuclei, httpx, etc.) — report those to the respective upstream projects.
- Deployments still using the legacy `admin`/`admin` account seeded by PEEK ≤ 2.2.1, or `SECRET_KEY=change_in_production` placeholders. Current versions no longer seed a default password (see "Initial admin account" below) and refuse weak `SECRET_KEY` values; an existing account is deliberately left untouched on upgrade and must be rotated by the operator.
- Findings produced by running PEEK against `scripts/qa/setup-hellbox-v3.sh` — this is a deliberately vulnerable QA target.
- Self-XSS or social-engineering issues that require a user to deliberately paste attacker-controlled content into their own browser console.

## Initial admin account

- On first start (no user named `admin` yet) the backend creates the `admin` account with the password from the `INITIAL_ADMIN_PASSWORD` environment variable. The value must satisfy the password policy; a weak value aborts startup.
- If the variable is unset, a random password is generated and printed once to the backend log. PEEK never seeds `admin`/`admin`.
- An existing `admin` account is never changed, so upgrades cannot lock anyone out. If that account still has the legacy password `admin`, the backend logs a `SECURITY` warning on every start until it is changed.
- Passwords are bcrypt hashes (cost `BCRYPT_ROUNDS`, default 12, upgraded on login). Passwords over 72 bytes or containing NUL are rejected when set; malformed stored hashes fail closed as a normal 401.
- `ALGORITHM` (JWT) is restricted to `HS256`/`HS384`/`HS512`.

## Scanner image supply chain

`backend/Dockerfile.celery` pins the base image by digest, verifies the nmap tarball and the nuclei/httpx/katana release archives by SHA-256, and pins nikto, testssl.sh and the nuclei template set to commit SHAs. The scanners run as an unprivileged user with file capabilities instead of root or `sudo`. Debian packages installed with `apt` are not version-pinned.

## Safe-Harbor

If you make a good-faith effort to comply with this policy during your security research, we will not pursue legal action against you. Please do not access, modify, or delete data belonging to other users; stop testing and contact us as soon as you discover a vulnerability.
