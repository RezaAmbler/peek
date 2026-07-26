"""
Tests for cross-scan triage memory (FindingState upsert).

A human triage decision (e.g. false_positive) must persist across scans: a second
scan of the same fingerprint refreshes last_seen_* but never resets status.
"""

import uuid
import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
import app.models  # noqa: F401  (register all tables)
from app.models import Scan, ScanTarget, Vulnerability, FindingState
from app.models.finding_state import FINDING_STATUSES
from app.schemas.finding_state import FindingStateUpdate
from app.services.fingerprint import finding_fingerprint
from app.services.finding_state_service import upsert_finding_states


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


def _make_scan(db, config_id="config-1"):
    scan = Scan(
        id=str(uuid.uuid4()),
        user_id="user-1",
        created_by_id="user-1",
        config_id=config_id,
        name="scan",
        status="completed",
    )
    db.add(scan)
    db.flush()
    target = ScanTarget(
        id=str(uuid.uuid4()), scan_id=str(scan.id), ip_address="10.0.0.5"
    )
    db.add(target)
    db.flush()
    return scan, target


def _add_vuln(db, target, template_id="CVE-2024-1", port=443, matched_at="https://10.0.0.5/"):
    fp = finding_fingerprint(host="10.0.0.5", template_id=template_id, port=port, matched_at=matched_at)
    db.add(Vulnerability(
        id=str(uuid.uuid4()),
        scan_target_id=str(target.id),
        template_id=template_id,
        name=template_id,
        severity="critical",
        matched_at=matched_at,
        host="10.0.0.5",
        port=port,
        fingerprint=fp,
    ))
    return fp


def test_upsert_creates_open_state(db):
    scan, target = _make_scan(db)
    fp = _add_vuln(db, target)
    db.commit()

    processed = upsert_finding_states(db, str(scan.id))
    assert processed == 1

    state = db.query(FindingState).filter(
        FindingState.config_id == "config-1", FindingState.fingerprint == fp
    ).one()
    assert state.status == "open"
    assert state.first_seen_scan_id == str(scan.id)
    assert state.last_seen_scan_id == str(scan.id)


def test_triage_decision_persists_across_scans(db):
    # Scan 1: creates the state.
    scan1, target1 = _make_scan(db)
    fp = _add_vuln(db, target1)
    db.commit()
    upsert_finding_states(db, str(scan1.id))

    # Human marks it false_positive.
    state = db.query(FindingState).filter(FindingState.fingerprint == fp).one()
    state.status = "false_positive"
    state.owner = "analyst"
    db.commit()
    first_seen_scan = state.first_seen_scan_id

    # Scan 2 (same config, same fingerprint): status must NOT be reset.
    scan2, target2 = _make_scan(db)
    _add_vuln(db, target2)
    db.commit()
    upsert_finding_states(db, str(scan2.id))

    db.refresh(state)
    assert state.status == "false_positive"       # human decision carried forward
    assert state.owner == "analyst"
    assert state.first_seen_scan_id == first_seen_scan  # unchanged
    assert state.last_seen_scan_id == str(scan2.id)     # advanced
    # Still exactly one state row (upsert, not insert).
    assert db.query(FindingState).filter(FindingState.fingerprint == fp).count() == 1


def test_upsert_is_idempotent(db):
    scan, target = _make_scan(db)
    _add_vuln(db, target)
    db.commit()
    upsert_finding_states(db, str(scan.id))
    upsert_finding_states(db, str(scan.id))
    assert db.query(FindingState).count() == 1


# --- Triage-API status validation (the exact validator the PATCH endpoint uses,
# testable without FastAPI installed) --------------------------------------


def test_schema_accepts_every_allowed_status():
    for status in FINDING_STATUSES:
        assert FindingStateUpdate(status=status).status == status


def test_schema_rejects_invalid_status():
    with pytest.raises(ValidationError):
        FindingStateUpdate(status="not_a_real_status")


def test_schema_allows_partial_update_without_status():
    upd = FindingStateUpdate(owner="analyst")
    # status omitted -> None, and excluded from a partial dump.
    assert upd.status is None
    assert "status" not in upd.model_dump(exclude_unset=True)
