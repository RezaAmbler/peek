"""
Tests for suppression-aware comparison.

A finding present only in the CURRENT scan is normally counted as a new
vulnerability. If a persistent FindingState marks it false_positive /
accepted_risk (or suppressed_until in the future), it must be classified
SUPPRESSED and NOT counted as new. With NO FindingState row, behavior is
unchanged (counted new) — this guards the existing de-noising tests.
"""

import uuid
from datetime import timedelta
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.timeutil import utcnow
from app.database import Base
import app.models  # noqa: F401
from app.models import Scan, ScanTarget, Vulnerability, FindingState
from app.services.comparison_service import ComparisonService
from app.services.fingerprint import finding_fingerprint

CONFIG_ID = "config-1"


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _make_scan(db, name):
    scan = Scan(
        id=str(uuid.uuid4()), user_id="user-1", created_by_id="user-1",
        config_id=CONFIG_ID, name=name, status="completed",
    )
    db.add(scan)
    db.flush()
    target = ScanTarget(id=str(uuid.uuid4()), scan_id=str(scan.id), ip_address="10.0.0.5")
    db.add(target)
    db.flush()
    return scan, target


def _add_vuln(db, target, template_id, port, matched_at, severity="critical"):
    fp = finding_fingerprint(host="10.0.0.5", template_id=template_id, port=port, matched_at=matched_at)
    db.add(Vulnerability(
        id=str(uuid.uuid4()), scan_target_id=str(target.id), template_id=template_id,
        name=template_id, severity=severity, matched_at=matched_at, host="10.0.0.5",
        port=port, fingerprint=fp,
    ))
    return fp


def _run(db, baseline, current):
    return ComparisonService(db).compare_scans(
        baseline_scan_id=str(baseline.id), current_scan_id=str(current.id), user_id="user-1"
    )


def test_new_finding_counted_when_no_state(db):
    """Guard the default path: no FindingState -> finding is counted new."""
    baseline, b_t = _make_scan(db, "baseline")
    current, c_t = _make_scan(db, "current")
    _add_vuln(db, c_t, "CVE-2024-9999", 8080, "http://10.0.0.5:8080/admin")
    db.commit()

    cmp = _run(db, baseline, current)
    assert cmp.new_vulnerabilities == 1
    new = [c for c in cmp.changes if c["type"] == "NEW_VULNERABILITY"]
    assert new[0]["classification"] == "GENUINELY_NEW"


def test_false_positive_finding_is_suppressed(db):
    """Same finding, but FindingState false_positive -> SUPPRESSED, not counted."""
    baseline, b_t = _make_scan(db, "baseline")
    current, c_t = _make_scan(db, "current")
    fp = _add_vuln(db, c_t, "CVE-2024-9999", 8080, "http://10.0.0.5:8080/admin")
    db.add(FindingState(
        id=str(uuid.uuid4()), config_id=CONFIG_ID, fingerprint=fp,
        name="CVE-2024-9999", status="false_positive",
    ))
    db.commit()

    cmp = _run(db, baseline, current)
    assert cmp.new_vulnerabilities == 0
    new = [c for c in cmp.changes if c["type"] == "NEW_VULNERABILITY"]
    assert len(new) == 1                      # still surfaced in the changes list
    assert new[0]["classification"] == "SUPPRESSED"


def test_future_suppressed_until_is_suppressed(db):
    baseline, b_t = _make_scan(db, "baseline")
    current, c_t = _make_scan(db, "current")
    fp = _add_vuln(db, c_t, "CVE-2024-9999", 8080, "http://10.0.0.5:8080/admin")
    db.add(FindingState(
        id=str(uuid.uuid4()), config_id=CONFIG_ID, fingerprint=fp, status="open",
        suppressed_until=utcnow() + timedelta(days=7),
    ))
    db.commit()

    cmp = _run(db, baseline, current)
    assert cmp.new_vulnerabilities == 0


def test_expired_suppressed_until_is_counted(db):
    """A past suppressed_until does not suppress (status still open)."""
    baseline, b_t = _make_scan(db, "baseline")
    current, c_t = _make_scan(db, "current")
    fp = _add_vuln(db, c_t, "CVE-2024-9999", 8080, "http://10.0.0.5:8080/admin")
    db.add(FindingState(
        id=str(uuid.uuid4()), config_id=CONFIG_ID, fingerprint=fp, status="open",
        suppressed_until=utcnow() - timedelta(days=1),
    ))
    db.commit()

    cmp = _run(db, baseline, current)
    assert cmp.new_vulnerabilities == 1
