---
name: Bug report
about: Report a defect in PEEK
title: "[bug] "
labels: bug
assignees: ''
---

## Description

A clear and concise description of the bug.

## Steps to Reproduce

1. ...
2. ...
3. ...

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened. Include error messages, stack traces, or screenshots if helpful.

## Environment

- **PEEK version / commit SHA**: <e.g., `9b65007`>
- **Deployment**: Docker Compose / local dev / production
- **OS**: <e.g., macOS 14.5, Ubuntu 22.04>
- **Browser** (if frontend bug): <e.g., Chrome 124>
- **Python version** (if backend bug): <e.g., 3.11.6>
- **Node version** (if frontend bug): <e.g., 20.10.0>

## Logs

```
Paste relevant logs from `docker compose logs -f celery` or
`docker compose logs -f backend` here.
```

## Scan Configuration (if scan-related)

If the bug involves a scan, paste the relevant fields from the `ScanConfig` (sanitize any internal target IPs):

```json
{
  "scan_mode": "...",
  "nuclei_severity": "...",
  "enable_*": ...
}
```

## Additional Context

Anything else that might help — related issues, recent changes, network conditions, etc.
