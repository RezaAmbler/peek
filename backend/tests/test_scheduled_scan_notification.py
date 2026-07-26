"""
Tests for the alert_on_critical notification gate (W1).

Previously the gate fired on ANY finding (scan.total_vulnerabilities > 0). It must
fire only when the scan has at least one critical-severity finding.
"""

import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
import app.models  # noqa: F401  (register all tables)
from app.models import Scan, ScanTarget, Vulnerability, ScheduledScan
from app.tasks import scheduled_scan_tasks


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


def _setup_scan(db, severities):
    scan = Scan(
        id=str(uuid.uuid4()),
        user_id="user-1",
        created_by_id="user-1",
        config_id="config-1",
        name="scan",
        status="completed",
        total_vulnerabilities=len(severities),
    )
    db.add(scan)
    db.flush()
    target = ScanTarget(
        id=str(uuid.uuid4()), scan_id=str(scan.id), ip_address="10.0.0.5"
    )
    db.add(target)
    db.flush()
    for i, sev in enumerate(severities):
        db.add(Vulnerability(
            id=str(uuid.uuid4()),
            scan_target_id=str(target.id),
            template_id=f"tpl-{i}",
            name=f"finding-{i}",
            severity=sev,
            matched_at=f"http://10.0.0.5/{i}",
            host="10.0.0.5",
            port=80,
        ))
    db.commit()
    return scan


def _make_scheduled_scan():
    # alert_on_critical only; email_on_completion off so the critical gate is the
    # sole trigger. Recipients present so we get past the early return.
    return ScheduledScan(
        id=str(uuid.uuid4()),
        user_id="user-1",
        created_by_id="user-1",
        name="nightly",
        cron_expression="0 2 * * *",
        config_id="config-1",
        targets=[{"ip_address": "10.0.0.5"}],
        email_recipients=["soc@example.com"],
        email_on_completion=False,
        email_on_changes_only=False,
        alert_on_critical=True,
        alert_on_new_vulns=False,
    )


@pytest.fixture
def captured_email(monkeypatch):
    calls = []

    from app.services import email_service

    def fake_send(**kwargs):
        calls.append(kwargs)
        return True

    monkeypatch.setattr(
        email_service.EmailService, "send_scan_completion_email", staticmethod(fake_send)
    )
    return calls


def test_alert_fires_when_critical_present(db, captured_email):
    scan = _setup_scan(db, ["critical", "low"])
    scheduled = _make_scheduled_scan()

    scheduled_scan_tasks.send_notification(scheduled, scan, comparison=None, db=db)

    assert len(captured_email) == 1


def test_alert_does_not_fire_for_low_medium_only(db, captured_email):
    scan = _setup_scan(db, ["low", "medium", "high"])
    scheduled = _make_scheduled_scan()

    scheduled_scan_tasks.send_notification(scheduled, scan, comparison=None, db=db)

    assert captured_email == []


def test_count_critical_vulnerabilities(db):
    scan = _setup_scan(db, ["critical", "critical", "high", "low"])
    assert scheduled_scan_tasks.count_critical_vulnerabilities(db, scan) == 2
