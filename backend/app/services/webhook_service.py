"""
Outbound push — let findings LEAVE the tool (generic webhook + Slack).

Best-effort, exactly like email_service: a scheduled scan that produced NEW
critical findings or any KEV-listed (actively-exploited) finding POSTs a compact
summary to an optional generic webhook and/or a Slack-compatible incoming
webhook. Design constraints (mirroring enrichment_service):

  - Short timeout (<=8s) so a slow endpoint can't stall post-scan processing.
  - Every network call is wrapped; this module NEVER raises to its caller.
  - Suppression-aware: findings a human triaged as false_positive / accepted_risk
    (or time-boxed via suppressed_until) are excluded from the trigger and payload.
  - Only attempts a channel whose URL is configured.
  - requests honors HTTPS_PROXY from the environment automatically.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from sqlalchemy.orm import Session

from ..core.config import settings
from ..models import FindingState, ScanTarget, Vulnerability
from ..models.finding_state import SUPPRESSED_STATUSES

logger = logging.getLogger(__name__)

# Short timeout so a slow/blocked webhook can't stall post-scan processing.
HTTP_TIMEOUT_SECONDS = 8

# How many findings to include in the compact payload (highest risk first).
TOP_FINDINGS = 5


def _suppression_map(db: Session, config_id: str) -> Dict[str, FindingState]:
    """fingerprint -> FindingState for this config (for suppression checks)."""
    if not config_id:
        return {}
    rows = db.query(FindingState).filter(FindingState.config_id == config_id).all()
    return {r.fingerprint: r for r in rows}


def _is_suppressed(state: Optional[FindingState]) -> bool:
    if state is None:
        return False
    if state.status in SUPPRESSED_STATUSES:
        return True
    if state.suppressed_until and state.suppressed_until > datetime.utcnow():
        return True
    return False


def gather_trigger_findings(db: Session, scan) -> Dict[str, Any]:
    """
    Collect the findings that should trigger an outbound alert for ``scan``.

    A finding triggers if it is critical-severity OR KEV-flagged (actively
    exploited), and is NOT suppressed by persistent triage state. Returns a dict:
        {
          'new_critical': int,     # non-suppressed critical findings
          'kev_listed': int,       # non-suppressed KEV-flagged findings
          'findings': [ {..}, .. ] # de-duped triggering findings, risk-desc
        }
    """
    vulns = (
        db.query(Vulnerability)
        .join(ScanTarget, Vulnerability.scan_target_id == ScanTarget.id)
        .filter(ScanTarget.scan_id == str(scan.id))
        .all()
    )

    states = _suppression_map(db, scan.config_id)

    new_critical = 0
    kev_listed = 0
    findings: List[Dict[str, Any]] = []
    seen_fp = set()

    for v in vulns:
        is_critical = (v.severity or "").lower() == "critical"
        is_kev = bool(v.kev_flag)
        if not (is_critical or is_kev):
            continue

        if _is_suppressed(states.get(v.fingerprint)):
            continue

        if is_critical:
            new_critical += 1
        if is_kev:
            kev_listed += 1

        fp = v.fingerprint or f"{v.host}:{v.template_id}:{v.port}"
        if fp in seen_fp:
            continue
        seen_fp.add(fp)
        findings.append({
            "name": v.name,
            "severity": v.severity,
            "cve_id": v.cve_id,
            "kev_flag": bool(v.kev_flag),
            "risk_score": v.risk_score,
            "host": v.host,
            "port": v.port,
            "matched_at": v.matched_at,
        })

    findings.sort(key=lambda f: (f.get("risk_score") or 0.0), reverse=True)

    return {
        "new_critical": new_critical,
        "kev_listed": kev_listed,
        "findings": findings,
    }


def _scan_target_str(db: Session, scan) -> str:
    """Human-readable target string for the payload (comma-joined IPs)."""
    targets = (
        db.query(ScanTarget.ip_address)
        .filter(ScanTarget.scan_id == str(scan.id))
        .all()
    )
    ips = [t[0] for t in targets if t[0]]
    if not ips:
        return ""
    if len(ips) <= 3:
        return ", ".join(ips)
    return f"{', '.join(ips[:3])} (+{len(ips) - 3} more)"


def build_generic_payload(scan, target: str, trigger: Dict[str, Any]) -> Dict[str, Any]:
    """Compact structured JSON payload for the generic webhook."""
    return {
        "event": "scan.findings",
        "scan": {
            "id": str(scan.id),
            "name": scan.name,
            "target": target,
            "total_vulnerabilities": getattr(scan, "total_vulnerabilities", None),
        },
        "summary": {
            "new_critical": trigger["new_critical"],
            "kev_listed": trigger["kev_listed"],
        },
        "top_findings": trigger["findings"][:TOP_FINDINGS],
    }


def build_slack_payload(scan, target: str, trigger: Dict[str, Any]) -> Dict[str, Any]:
    """Slack incoming-webhook payload (text + blocks)."""
    headline = (
        f"PEEK: {trigger['new_critical']} new critical, "
        f"{trigger['kev_listed']} KEV-listed finding(s) on {target or 'target'}"
    )
    lines = [f"*{scan.name or 'Scan'}* — {target or 'target'}"]
    for f in trigger["findings"][:TOP_FINDINGS]:
        kev = " :rotating_light:KEV" if f.get("kev_flag") else ""
        risk = f" (risk {f['risk_score']})" if f.get("risk_score") is not None else ""
        cve = f" [{f['cve_id']}]" if f.get("cve_id") else ""
        lines.append(f"• *{f.get('severity', '?')}*{kev} {f.get('name')}{cve}{risk} — {f.get('host')}:{f.get('port')}")

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": headline[:150]}},
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)[:2900]}},
    ]
    return {"text": headline, "blocks": blocks}


def _post(url: str, payload: Dict[str, Any], label: str) -> bool:
    """POST payload as JSON. Best-effort: logs and returns False on any failure."""
    try:
        resp = requests.post(url, json=payload, timeout=HTTP_TIMEOUT_SECONDS)
        resp.raise_for_status()
        logger.info(f"Webhook ({label}) delivered: {resp.status_code}")
        return True
    except Exception as e:  # noqa: BLE001 - best-effort by design
        logger.warning(f"Webhook ({label}) delivery failed: {e}")
        return False


def notify_scan_findings(db: Session, scan) -> bool:
    """
    Fire outbound webhook(s) for a completed scan if it has non-suppressed NEW
    critical or KEV-listed findings and at least one webhook URL is configured.

    Returns True if any webhook was attempted+delivered. Never raises.
    """
    try:
        webhook_url = (settings.WEBHOOK_URL or "").strip()
        slack_url = (settings.SLACK_WEBHOOK_URL or "").strip()

        # No channel configured -> nothing to do (don't even query findings).
        if not webhook_url and not slack_url:
            return False

        trigger = gather_trigger_findings(db, scan)
        if trigger["new_critical"] == 0 and trigger["kev_listed"] == 0:
            logger.info(f"Webhook: no new-critical/KEV trigger for scan {scan.id}, skipping")
            return False

        target = _scan_target_str(db, scan)
        delivered = False

        if webhook_url:
            payload = build_generic_payload(scan, target, trigger)
            delivered = _post(webhook_url, payload, "generic") or delivered

        if slack_url:
            payload = build_slack_payload(scan, target, trigger)
            delivered = _post(slack_url, payload, "slack") or delivered

        return delivered
    except Exception as e:  # noqa: BLE001 - never propagate to the scan pipeline
        logger.warning(f"Webhook notify failed for scan {getattr(scan, 'id', '?')} (non-fatal): {e}")
        return False
