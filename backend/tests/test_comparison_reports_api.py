"""
Comparison report endpoints (routers/reports.py): every export format is served
for a comparison the caller may read, and refused otherwise.

Exercises the async endpoint functions directly. The endpoints check access on
the async session and render through a sync session, so both are bound to one
SQLite file.
"""
import uuid
from contextlib import contextmanager
from datetime import datetime
from types import SimpleNamespace

import pytest
import pytest_asyncio

pytest.importorskip("fastapi")

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import sessionmaker

from app.database import Base
import app.models  # noqa: F401
from app.models import Scan, ScanComparison, ScanConfig
from app.routers import reports as reports_router
from app.routers.auth import get_current_user

COMPARISON_ID = "0a1b2c3d-0000-4000-8000-000000000001"

CHANGES = [
    {"type": "NEW_PORT", "severity": "HIGH", "category": "port", "ip_address": "10.0.0.5",
     "port": 8443, "protocol": "tcp", "service_name": "https", "description": "New port"},
    {"type": "NEW_VULNERABILITY", "severity": "CRITICAL", "category": "vulnerability",
     "ip_address": "10.0.0.5", "port": 443, "name": "RCE", "template_id": "CVE-2026-0001",
     "vuln_severity": "critical", "classification": "GENUINELY_NEW", "description": "New vuln"},
]


def _scan(scan_id, user_id, run_number, day):
    return Scan(
        id=scan_id, user_id=user_id, created_by_id=user_id, config_id="config-1", name="run",
        status="completed", run_number=run_number,
        created_at=datetime(2026, 10, day, 8, 0, 0),
        started_at=datetime(2026, 10, day, 8, 0, 5),
        finished_at=datetime(2026, 10, day, 8, 42, 10),
    )


@pytest_asyncio.fixture
async def adb(tmp_path, monkeypatch):
    path = tmp_path / "reports.db"
    sync_engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(sync_engine)
    SyncSession = sessionmaker(bind=sync_engine)

    with SyncSession() as session:
        session.add(ScanConfig(id="config-1", user_id="user-1", name="office-network"))
        session.add_all([_scan("baseline", "user-1", 2, 3), _scan("current", "user-1", 3, 10)])
        session.add(ScanComparison(
            id=COMPARISON_ID, baseline_scan_id="baseline", current_scan_id="current",
            created_by_id="user-1", created_at=datetime(2026, 10, 10, 20, 15, 0),
            total_changes=2, new_ports=1, new_vulnerabilities=1, critical_changes=1,
            high_changes=1, changes=CHANGES,
        ))
        session.commit()

    @contextmanager
    def sync_db():
        with SyncSession() as session:
            yield session

    monkeypatch.setattr(reports_router, "get_sync_db", sync_db)

    async_engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    Session = async_sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as session:
        yield session
    await async_engine.dispose()
    sync_engine.dispose()


def _user(uid="user-1", admin=False):
    return SimpleNamespace(id=uid, is_admin=admin)


async def _body(response) -> bytes:
    chunks = [chunk async for chunk in response.body_iterator]
    return b"".join(c.encode() if isinstance(c, str) else c for c in chunks)


ENDPOINTS = [
    (reports_router.get_comparison_report_pdf, {}),
    (reports_router.get_comparison_executive_pdf, {}),
    (reports_router.get_comparison_html_report, {}),
    (reports_router.export_comparison_changes_csv, {"category": None}),
    (reports_router.export_comparison_summary_csv, {}),
]
endpoints = pytest.mark.parametrize("endpoint, extra", ENDPOINTS, ids=lambda v: getattr(v, "__name__", ""))


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint, media_type, filename, starts_with", [
    (reports_router.get_comparison_report_pdf, "application/pdf",
     "comparison_report_0a1b2c3d.pdf", b"%PDF"),
    (reports_router.get_comparison_executive_pdf, "application/pdf",
     "comparison_executive_summary_0a1b2c3d.pdf", b"%PDF"),
    (reports_router.export_comparison_summary_csv, "text/csv",
     "comparison_summary_0a1b2c3d.csv", b"Compared At (UTC),"),
])
async def test_comparison_downloads(adb, endpoint, media_type, filename, starts_with):
    response = await endpoint(comparison_id=COMPARISON_ID, current_user=_user(), db=adb)

    assert response.media_type == media_type
    assert response.headers["content-disposition"] == f"attachment; filename={filename}"
    assert (await _body(response)).startswith(starts_with)


@pytest.mark.asyncio
async def test_comparison_html_is_served_as_a_download(adb):
    response = await reports_router.get_comparison_html_report(
        comparison_id=COMPARISON_ID, current_user=_user(), db=adb)
    html = (await _body(response)).decode()

    assert response.media_type == "text/html"
    # attachment: the report is never rendered on the API's own origin
    assert response.headers["content-disposition"] == "attachment; filename=comparison_report_0a1b2c3d.html"
    assert "Scan Comparison Report" in html and "10.0.0.5:8443/tcp" in html
    assert "<strong>Compared:</strong> 2026-10-10 20:15 UTC" in html


@pytest.mark.asyncio
async def test_comparison_changes_csv_all_and_by_category(adb):
    everything = await reports_router.export_comparison_changes_csv(
        comparison_id=COMPARISON_ID, category=None, current_user=_user(), db=adb)
    vulns = await reports_router.export_comparison_changes_csv(
        comparison_id=COMPARISON_ID, category="vulnerability", current_user=_user(), db=adb)

    assert everything.headers["content-disposition"] == "attachment; filename=comparison_changes_0a1b2c3d.csv"
    assert vulns.headers["content-disposition"] == (
        "attachment; filename=comparison_vulnerability_changes_0a1b2c3d.csv")
    assert len((await _body(everything)).decode().splitlines()) == 3
    vuln_lines = (await _body(vulns)).decode().splitlines()
    assert len(vuln_lines) == 2 and vuln_lines[1].startswith("NEW_VULNERABILITY,vulnerability,CRITICAL,")


@pytest.mark.asyncio
@endpoints
async def test_admin_can_export_any_comparison(adb, endpoint, extra):
    response = await endpoint(
        comparison_id=COMPARISON_ID, current_user=_user("someone-else", admin=True), db=adb, **extra)

    assert len(await _body(response)) > 0


@pytest.mark.asyncio
@endpoints
async def test_other_users_cannot_export(adb, endpoint, extra):
    with pytest.raises(HTTPException) as exc:
        await endpoint(comparison_id=COMPARISON_ID, current_user=_user("other-user"), db=adb, **extra)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
@endpoints
async def test_owning_only_one_of_the_scans_is_not_enough(adb, endpoint, extra):
    current = await adb.get(Scan, "current")
    current.user_id = "other-user"
    await adb.commit()

    for uid in ("user-1", "other-user"):
        with pytest.raises(HTTPException) as exc:
            await endpoint(comparison_id=COMPARISON_ID, current_user=_user(uid), db=adb, **extra)
        assert exc.value.status_code == 403


@pytest.mark.asyncio
@endpoints
async def test_unknown_comparison_404(adb, endpoint, extra):
    with pytest.raises(HTTPException) as exc:
        await endpoint(comparison_id=str(uuid.uuid4()), current_user=_user(), db=adb, **extra)
    assert exc.value.status_code == 404


def test_every_report_route_requires_an_authenticated_user():
    routes = [r for r in reports_router.router.routes if hasattr(r, "dependant")]

    comparison_paths = {r.path for r in routes if r.path.startswith("/comparison/")}
    assert comparison_paths == {
        "/comparison/{comparison_id}/pdf",
        "/comparison/{comparison_id}/pdf/detailed",
        "/comparison/{comparison_id}/pdf/executive",
        "/comparison/{comparison_id}/html",
        "/comparison/{comparison_id}/csv/changes",
        "/comparison/{comparison_id}/csv/summary",
    }
    for route in routes:
        assert get_current_user in [d.call for d in route.dependant.dependencies], route.path


def test_changes_csv_rejects_an_unknown_category():
    route = next(r for r in reports_router.router.routes
                 if getattr(r, "path", "") == "/comparison/{comparison_id}/csv/changes")
    category = next(p for p in route.dependant.query_params if p.name == "category")

    assert category.validate("vulnerability", {}, loc=("query", "category"))[1] in (None, [])
    assert category.validate("users", {}, loc=("query", "category"))[1]
