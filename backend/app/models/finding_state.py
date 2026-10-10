"""
Cross-scan triage state for findings (the "memory" layer).

A raw Vulnerability row lives and dies with a single scan. But a human triage
decision — "this is a false positive", "we accept this risk until Q3" — must
survive across scans so the same finding is not re-surfaced every run.

FindingState is that persistent memory. It is keyed by (config_id, fingerprint):

  - ``fingerprint`` is the stable sha256 identity of a logical finding (see
    services/fingerprint.py) that already survives ephemeral-port / crawl-URL
    churn, so the same logical finding maps to the same state across runs.
  - ``config_id`` scopes triage the same way the comparison feature is scoped:
    a config defines a comparable series of scans, and it is always present on a
    scan. Scoping to the config (not an individual scan) is what lets a decision
    persist from one run to the next.

The scanner only ever touches last_seen_*/cve_id/name (the observed facts). The
status/owner/triage_notes/suppressed_until columns are HUMAN decisions and are
never overwritten by an automated upsert — see services/finding_state_service.py.
"""

from sqlalchemy import Column, String, DateTime, ForeignKey, UniqueConstraint, Index
from datetime import datetime
import uuid
from ..database import Base
from ..core.timeutil import utcnow


# Allowed triage lifecycle states. Kept here (single source of truth) so the
# model, the API validator and the suppression logic all agree.
FINDING_STATUSES = (
    "open",            # newly seen / untriaged
    "triaged",         # a human has looked at it (no suppression implied)
    "false_positive",  # not a real finding -> suppress
    "accepted_risk",   # real but accepted -> suppress
    "fixed",           # remediated
)

# Statuses that suppress a finding from being re-surfaced as NEW in comparison
# and from triggering outbound alerts.
SUPPRESSED_STATUSES = frozenset({"false_positive", "accepted_risk"})


class FindingState(Base):
    __tablename__ = "finding_states"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Triage scope: a finding's memory is keyed by (config_id, fingerprint).
    config_id = Column(String(36), ForeignKey("scan_configs.id"), nullable=False, index=True)
    organization_id = Column(String(36), nullable=True, index=True)

    # Stable logical-finding identity (see services/fingerprint.py).
    fingerprint = Column(String(64), nullable=False, index=True)

    # Display / correlation aids (observed facts, safe to refresh).
    cve_id = Column(String, nullable=True)
    name = Column(String, nullable=True)

    # --- Human triage decision (never overwritten by the scanner) -----------
    status = Column(String, nullable=False, default="open")
    owner = Column(String, nullable=True)
    triage_notes = Column(String, nullable=True)
    suppressed_until = Column(DateTime, nullable=True)

    # --- Observed lifecycle (maintained by the upsert on every scan) --------
    first_seen_at = Column(DateTime, default=utcnow, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=True)
    first_seen_scan_id = Column(String(36), nullable=True)
    last_seen_scan_id = Column(String(36), nullable=True)

    __table_args__ = (
        UniqueConstraint("config_id", "fingerprint", name="uq_finding_state_config_fp"),
        Index("ix_finding_states_config_fp", "config_id", "fingerprint"),
    )
