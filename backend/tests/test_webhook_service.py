"""
Tests for the outbound webhook / Slack push.

The webhook fires only when a URL is configured AND the scan has a non-suppressed
new-critical/KEV trigger. No URL or no trigger -> no POST. A raising POST must not
propagate (best-effort, like email_service).
"""

import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
import app.models  # noqa: F401
from app.models import Scan, ScanTarget, Vulnerability, FindingState
from app.services.fingerprint import finding_fingerprint
from app.services import webhook_service


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


@pytest.fixture
def captured_posts(monkeypatch):
    calls = []

    class _Resp:
        status_code = 200
        def raise_for_status(self):
            return None

    def fake_post(url, json=None, timeout=None):
        calls.append({"url": url, "json": json, "timeout": timeout})
        return _Resp()

    monkeypatch.setattr(webhook_service.requests, "post", fake_post)
    return calls


def _make_scan(db, config_id="config-1"):
    scan = Scan(
        id=str(uuid.uuid4()), user_id="user-1", created_by_id="user-1",
        config_id=config_id, name="nightly", status="completed",
        total_vulnerabilities=1,
    )
    db.add(scan)
    db.flush()
    target = ScanTarget(id=str(uuid.uuid4()), scan_id=str(scan.id), ip_address="10.0.0.5")
    db.add(target)
    db.flush()
    return scan, target


def _add_vuln(db, target, severity="critical", kev=False, template_id="CVE-2024-1", risk=88.0):
    fp = finding_fingerprint(host="10.0.0.5", template_id=template_id, port=443, matched_at="https://10.0.0.5/")
    db.add(Vulnerability(
        id=str(uuid.uuid4()), scan_target_id=str(target.id), template_id=template_id,
        name=template_id, severity=severity, matched_at="https://10.0.0.5/", host="10.0.0.5",
        port=443, fingerprint=fp, kev_flag=kev, cve_id=template_id, risk_score=risk,
    ))
    return fp


def test_posts_when_url_and_critical_trigger(db, captured_posts, monkeypatch):
    monkeypatch.setattr(webhook_service.settings, "WEBHOOK_URL", "https://hook.example/generic")
    monkeypatch.setattr(webhook_service.settings, "SLACK_WEBHOOK_URL", "")
    scan, target = _make_scan(db)
    _add_vuln(db, target, severity="critical")
    db.commit()

    result = webhook_service.notify_scan_findings(db, scan)
    assert result is True
    assert len(captured_posts) == 1
    payload = captured_posts[0]["json"]
    assert payload["summary"]["new_critical"] == 1
    assert payload["scan"]["target"] == "10.0.0.5"
    assert payload["top_findings"][0]["name"] == "CVE-2024-1"


def test_posts_on_kev_even_without_critical(db, captured_posts, monkeypatch):
    monkeypatch.setattr(webhook_service.settings, "WEBHOOK_URL", "https://hook.example/generic")
    monkeypatch.setattr(webhook_service.settings, "SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")
    scan, target = _make_scan(db)
    _add_vuln(db, target, severity="high", kev=True)
    db.commit()

    result = webhook_service.notify_scan_findings(db, scan)
    assert result is True
    # Both generic + slack configured -> two POSTs.
    assert len(captured_posts) == 2
    urls = {c["url"] for c in captured_posts}
    assert "https://hook.example/generic" in urls
    assert "https://hooks.slack.com/services/x" in urls


def test_no_post_when_no_url(db, captured_posts, monkeypatch):
    monkeypatch.setattr(webhook_service.settings, "WEBHOOK_URL", "")
    monkeypatch.setattr(webhook_service.settings, "SLACK_WEBHOOK_URL", "")
    scan, target = _make_scan(db)
    _add_vuln(db, target, severity="critical")
    db.commit()

    result = webhook_service.notify_scan_findings(db, scan)
    assert result is False
    assert captured_posts == []


def test_no_post_when_no_trigger(db, captured_posts, monkeypatch):
    monkeypatch.setattr(webhook_service.settings, "WEBHOOK_URL", "https://hook.example/generic")
    monkeypatch.setattr(webhook_service.settings, "SLACK_WEBHOOK_URL", "")
    scan, target = _make_scan(db)
    _add_vuln(db, target, severity="low")  # not critical, not KEV
    db.commit()

    result = webhook_service.notify_scan_findings(db, scan)
    assert result is False
    assert captured_posts == []


def test_suppressed_critical_does_not_trigger(db, captured_posts, monkeypatch):
    monkeypatch.setattr(webhook_service.settings, "WEBHOOK_URL", "https://hook.example/generic")
    monkeypatch.setattr(webhook_service.settings, "SLACK_WEBHOOK_URL", "")
    scan, target = _make_scan(db)
    fp = _add_vuln(db, target, severity="critical")
    db.add(FindingState(
        id=str(uuid.uuid4()), config_id="config-1", fingerprint=fp, status="false_positive",
    ))
    db.commit()

    result = webhook_service.notify_scan_findings(db, scan)
    assert result is False
    assert captured_posts == []


def test_raising_post_does_not_propagate(db, monkeypatch):
    monkeypatch.setattr(webhook_service.settings, "WEBHOOK_URL", "https://hook.example/generic")
    monkeypatch.setattr(webhook_service.settings, "SLACK_WEBHOOK_URL", "")

    def boom(url, json=None, timeout=None):
        raise RuntimeError("network down")

    monkeypatch.setattr(webhook_service.requests, "post", boom)

    scan, target = _make_scan(db)
    _add_vuln(db, target, severity="critical")
    db.commit()

    # Must not raise; returns False because delivery failed.
    result = webhook_service.notify_scan_findings(db, scan)
    assert result is False
