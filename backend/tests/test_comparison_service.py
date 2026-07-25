"""
Tests for fingerprint-keyed, de-noised scan comparison.

Reproduces the live-QA "19 false new vulnerabilities" scenario: the same logical
findings reappear on different ephemeral ports and different crawl URLs after a
box was hardened. With stable fingerprints + ephemeral-port normalization the
comparison must report ~0 genuinely-new and ~0 fixed.
"""

import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
# Import all models so create_all builds the full schema (FKs resolve).
import app.models  # noqa: F401
from app.models import Scan, ScanTarget, Port, Vulnerability
from app.services.comparison_service import ComparisonService
from app.services.fingerprint import finding_fingerprint


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


def _make_scan(db, name):
    scan = Scan(
        id=str(uuid.uuid4()),
        user_id="user-1",
        created_by_id="user-1",
        config_id="config-1",
        name=name,
        status="completed",
    )
    db.add(scan)
    db.flush()
    target = ScanTarget(
        id=str(uuid.uuid4()),
        scan_id=str(scan.id),
        ip_address="10.0.0.5",
        device_name="web-box",
    )
    db.add(target)
    db.flush()
    return scan, target


def _add_vuln(db, target, template_id, port, matched_at, severity="high", set_fp=True):
    fp = finding_fingerprint(
        host="10.0.0.5", template_id=template_id, port=port, matched_at=matched_at
    ) if set_fp else None
    v = Vulnerability(
        id=str(uuid.uuid4()),
        scan_target_id=str(target.id),
        template_id=template_id,
        name=template_id,
        severity=severity,
        matched_at=matched_at,
        host="10.0.0.5",
        port=port,
        fingerprint=fp,
    )
    db.add(v)


def _add_port(db, target, port, service_name):
    p = Port(
        id=str(uuid.uuid4()),
        scan_target_id=str(target.id),
        port=port,
        protocol="tcp",
        state="open",
        service_name=service_name,
        discovered_by="nmap",
    )
    db.add(p)


def test_ephemeral_and_url_churn_is_not_new_or_fixed(db):
    """The same findings on rotated ephemeral ports / URLs -> 0 new, 0 fixed."""
    baseline, b_target = _make_scan(db, "baseline")
    current, c_target = _make_scan(db, "current")

    # Same three logical findings in both scans, but:
    #  - crawl URLs differ (query params / session tokens)
    #  - RPC-style findings land on different ephemeral high ports
    # Baseline rows intentionally have NULL fingerprint to exercise the fallback.
    baseline_findings = [
        ("tls-weak-cipher", 443, "https://10.0.0.5/index.html?sid=AAA"),
        ("rpc-portmapper", 49163, "rpc://10.0.0.5/"),
        ("nfs-export", 44971, "nfs://10.0.0.5/export"),
    ]
    current_findings = [
        ("tls-weak-cipher", 443, "https://10.0.0.5/index.html?sid=ZZZ&nonce=9"),
        ("rpc-portmapper", 50011, "rpc://10.0.0.5/"),
        ("nfs-export", 51234, "nfs://10.0.0.5/export"),
    ]
    for tid, port, url in baseline_findings:
        _add_vuln(db, b_target, tid, port, url, set_fp=False)  # legacy NULL fp
    for tid, port, url in current_findings:
        _add_vuln(db, c_target, tid, port, url, set_fp=True)

    # Matching port churn: RPC services on rotated ephemeral ports, 443 stable.
    _add_port(db, b_target, 443, "https")
    _add_port(db, b_target, 49163, "mountd")
    _add_port(db, b_target, 44971, "nlockmgr")
    _add_port(db, c_target, 443, "https")
    _add_port(db, c_target, 50011, "mountd")
    _add_port(db, c_target, 51234, "nlockmgr")
    db.commit()

    comparison = ComparisonService(db).compare_scans(
        baseline_scan_id=str(baseline.id),
        current_scan_id=str(current.id),
        user_id="user-1",
    )

    assert comparison.new_vulnerabilities == 0
    assert comparison.fixed_vulnerabilities == 0
    assert comparison.new_ports == 0
    assert comparison.closed_ports == 0


def test_genuinely_new_vulnerability_is_flagged(db):
    """A truly new finding still surfaces, annotated GENUINELY_NEW."""
    baseline, b_target = _make_scan(db, "baseline")
    current, c_target = _make_scan(db, "current")

    _add_vuln(db, b_target, "tls-weak-cipher", 443, "https://10.0.0.5/")
    # Current keeps that one AND adds a brand-new critical finding.
    _add_vuln(db, c_target, "tls-weak-cipher", 443, "https://10.0.0.5/")
    _add_vuln(db, c_target, "CVE-2024-9999", 8080, "http://10.0.0.5:8080/admin", severity="critical")
    db.commit()

    comparison = ComparisonService(db).compare_scans(
        baseline_scan_id=str(baseline.id),
        current_scan_id=str(current.id),
        user_id="user-1",
    )

    assert comparison.new_vulnerabilities == 1
    assert comparison.fixed_vulnerabilities == 0
    new_changes = [c for c in comparison.changes if c["type"] == "NEW_VULNERABILITY"]
    assert len(new_changes) == 1
    assert new_changes[0]["classification"] == "GENUINELY_NEW"
    assert new_changes[0]["template_id"] == "CVE-2024-9999"
