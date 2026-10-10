"""
Carry triage decisions forward across scans (the FindingState upsert).

Called once, best-effort, after a scan completes (see tasks/scan_tasks.py, right
after enrichment). For every Vulnerability in the completed scan it computes the
stable (config_id, fingerprint) key and upserts a FindingState row:

  - No existing row  -> INSERT with status='open', first_seen_* set to this scan.
  - Existing row     -> UPDATE only the OBSERVED facts (last_seen_at,
                        last_seen_scan_id, cve_id, name). The human-decision
                        columns (status/owner/triage_notes/suppressed_until) are
                        deliberately left untouched so a "false_positive" or
                        "accepted_risk" decision persists run-to-run.

Idempotent: re-running for the same scan only advances last_seen_* to the same
values and never resets triage state.
"""

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from ..models import FindingState, Scan, ScanTarget, Vulnerability
from .fingerprint import finding_fingerprint
from ..core.timeutil import utcnow

logger = logging.getLogger(__name__)


def _vuln_fingerprint(vuln: Vulnerability) -> Optional[str]:
    """Return the stored fingerprint, or compute it if a legacy row lacks one."""
    if vuln.fingerprint:
        return vuln.fingerprint
    # Backward-compat with rows ingested before the fingerprint column existed.
    return finding_fingerprint(
        host=vuln.host,
        template_id=vuln.template_id,
        port=vuln.port,
        matched_at=vuln.matched_at,
        cve_id=vuln.cve_id,
    )


def upsert_finding_states(db: Session, scan_id: str) -> int:
    """
    Insert/refresh a FindingState for every finding in the completed scan.

    Returns the number of findings processed. Commits once at the end.
    Human triage columns are never overwritten.
    """
    scan = db.query(Scan).filter(Scan.id == str(scan_id)).first()
    if not scan:
        logger.warning(f"upsert_finding_states: scan {scan_id} not found")
        return 0

    config_id = scan.config_id
    organization_id = scan.organization_id

    vulns = (
        db.query(Vulnerability)
        .join(ScanTarget, Vulnerability.scan_target_id == ScanTarget.id)
        .filter(ScanTarget.scan_id == str(scan_id))
        .all()
    )
    if not vulns:
        return 0

    now = utcnow()
    processed = 0
    # De-dupe within this scan: many rows can share one (config_id, fingerprint)
    # (same finding on multiple URLs). Track keys handled in-memory so we upsert
    # each state once per scan even before the flush is visible to queries.
    seen_keys = {}

    for vuln in vulns:
        fp = _vuln_fingerprint(vuln)
        if not fp:
            continue
        key = (config_id, fp)

        state = seen_keys.get(key)
        if state is None:
            state = (
                db.query(FindingState)
                .filter(
                    FindingState.config_id == config_id,
                    FindingState.fingerprint == fp,
                )
                .first()
            )

        if state is None:
            # First time this logical finding is seen for this config.
            state = FindingState(
                config_id=config_id,
                organization_id=organization_id,
                fingerprint=fp,
                cve_id=vuln.cve_id,
                name=vuln.name,
                status="open",
                first_seen_at=now,
                last_seen_at=now,
                first_seen_scan_id=str(scan_id),
                last_seen_scan_id=str(scan_id),
            )
            db.add(state)
        else:
            # Refresh only OBSERVED facts. NEVER touch status/owner/
            # triage_notes/suppressed_until — those are human decisions.
            state.last_seen_at = now
            state.last_seen_scan_id = str(scan_id)
            if vuln.cve_id:
                state.cve_id = vuln.cve_id
            if vuln.name:
                state.name = vuln.name

        seen_keys[key] = state
        processed += 1

    db.commit()
    logger.info(
        f"FindingState upsert: processed {processed} finding(s) "
        f"({len(seen_keys)} distinct) for scan {scan_id}"
    )
    return processed
