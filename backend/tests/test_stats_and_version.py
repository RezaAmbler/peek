"""
Dashboard statistics and build information.

The dashboard describes the current state: finding/port figures count only the
latest completed run of each config, so re-running the same targets does not
inflate them. Scan counters (total, by status) still cover every scan.
"""
import sqlite3
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
import pytest_asyncio

pytest.importorskip("fastapi")

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
import app.models  # noqa: F401
from app.models import Port, Scan, ScanConfig, ScanTarget, Vulnerability
from app.routers import stats as stats_router

T0 = datetime(2026, 10, 10, 12, 0, 0)


def _scan(session, config_id, run, status, severities, ports=2, user="user-1"):
    scan = Scan(
        id=str(uuid.uuid4()), user_id=user, created_by_id=user, config_id=config_id,
        run_number=run, status=status, created_at=T0 + timedelta(hours=run),
        total_open_ports=ports, total_vulnerabilities=len(severities),
    )
    target = ScanTarget(id=str(uuid.uuid4()), scan_id=scan.id, ip_address="10.0.0.5")
    session.add_all([scan, target])
    session.add(Port(id=str(uuid.uuid4()), scan_target_id=target.id, port=80, protocol="tcp",
                     state="open", service_name="http", discovered_by="nmap"))
    for index, severity in enumerate(severities):
        session.add(Vulnerability(
            id=str(uuid.uuid4()), scan_target_id=target.id, template_id=f"t-{index}",
            name=f"finding {index}", severity=severity, vuln_type="http",
            matched_at=f"http://10.0.0.5/{index}", host="10.0.0.5", port=80,
        ))
    return scan


@pytest_asyncio.fixture
async def adb():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as session:
        session.add(ScanConfig(id="config-a", user_id="user-1", name="a"))
        session.add(ScanConfig(id="config-b", user_id="user-1", name="b"))
        # config-a: three runs of the same target, then a failed and a cancelled one
        _scan(session, "config-a", 1, "completed", ["critical", "high", "info"])
        _scan(session, "config-a", 2, "completed", ["critical", "high", "medium", "info", "info"], ports=3)
        _scan(session, "config-a", 3, "failed", [])
        _scan(session, "config-a", 4, "cancelled", [])
        _scan(session, "config-b", 1, "completed", ["low"], ports=5)
        # Somebody else's scan never shows up
        _scan(session, "config-c", 1, "completed", ["critical"] * 4, user="user-2")
        await session.commit()
        yield session
    await engine.dispose()


def _user(uid="user-1"):
    return SimpleNamespace(id=uid, is_admin=False)


@pytest.mark.asyncio
async def test_scan_counters_cover_every_scan_including_failed(adb):
    stats = await stats_router.get_dashboard_stats(current_user=_user(), db=adb)

    by_status = {item.status: item.count for item in stats.scans_by_status}
    assert stats.total_scans == 5
    assert by_status == {"completed": 3, "failed": 1, "cancelled": 1}


@pytest.mark.asyncio
async def test_finding_totals_count_only_the_latest_completed_run_per_config(adb):
    stats = await stats_router.get_dashboard_stats(current_user=_user(), db=adb)

    severities = {item.severity: item.count for item in stats.vulnerabilities_by_severity}
    assert stats.findings_scope == "latest_completed_run_per_config"
    assert stats.scans_counted == 2  # config-a run 2 + config-b run 1
    assert severities == {"critical": 1, "high": 1, "medium": 1, "info": 2, "low": 1}
    assert stats.total_findings == 6
    assert stats.total_vulnerabilities == 4  # info findings are not vulnerabilities
    assert stats.total_findings_all_runs == 9  # 3 + 5 + 1, the old inflated figure
    assert stats.total_ports == 8  # 3 + 5, not 2 + 3 + 5
    assert stats.top_vulnerable_hosts[0].vulnerability_count == 6


@pytest.mark.asyncio
async def test_stats_for_a_user_without_scans(adb):
    stats = await stats_router.get_dashboard_stats(current_user=_user("nobody"), db=adb)

    assert stats.total_scans == 0 and stats.total_findings == 0 and stats.total_vulnerabilities == 0
    assert stats.scans_counted == 0 and stats.total_ports == 0


# ---------------------------------------------------------------------------
# Build information (/api/health, /api/version)
# ---------------------------------------------------------------------------

@pytest.fixture
def main_module():
    from app import main
    main.get_build_info.cache_clear()
    yield main
    main.get_build_info.cache_clear()


def test_build_info_comes_from_the_deploy_environment(main_module, monkeypatch):
    monkeypatch.setenv("GIT_BRANCH", "review/scan-security-2026-10")
    monkeypatch.setenv("GIT_COMMIT", "1d5e920")

    info = main_module.get_build_info()

    assert info["git_branch"] == "review/scan-security-2026-10"
    assert info["git_commit"] == "1d5e920"
    assert info["version"]


def test_build_info_is_null_not_unknown_when_git_is_unavailable(main_module, monkeypatch):
    monkeypatch.setenv("GIT_BRANCH", "unknown")
    monkeypatch.delenv("GIT_COMMIT", raising=False)
    monkeypatch.setattr(main_module, "_git_output", lambda *args: "")

    info = main_module.get_build_info()

    assert info["git_branch"] is None and info["git_commit"] is None


@pytest.mark.asyncio
async def test_health_and_version_endpoints_share_the_build_info(main_module, monkeypatch):
    monkeypatch.setenv("GIT_BRANCH", "main")
    monkeypatch.setenv("GIT_COMMIT", "abc1234")

    health = await main_module.health_check()
    version = await main_module.version_info()

    assert health["status"] == "ok"
    assert {key: health[key] for key in version} == version
    assert version["git_commit"] == "abc1234"


# ---------------------------------------------------------------------------
# Migration 004: scans.error_message
# ---------------------------------------------------------------------------

def test_migration_004_adds_and_backfills_scan_error_message(tmp_path):
    from migrations.apply_migrations import apply_004_scan_error_message

    conn = sqlite3.connect(tmp_path / "peek.db")
    cursor = conn.cursor()
    cursor.executescript(
        """
        CREATE TABLE scans (id VARCHAR PRIMARY KEY, status VARCHAR);
        CREATE TABLE scan_targets (id VARCHAR PRIMARY KEY, scan_id VARCHAR);
        CREATE TABLE tool_executions (id VARCHAR PRIMARY KEY, scan_target_id VARCHAR,
                                      error_message VARCHAR, finished_at DATETIME);
        INSERT INTO scans VALUES ('with-reason', 'failed'), ('no-reason', 'failed'), ('fine', 'completed');
        INSERT INTO scan_targets VALUES ('t1', 'with-reason'), ('t2', 'fine');
        INSERT INTO tool_executions VALUES
            ('e1', 't1', 'older failure', '2026-10-10 10:00:00'),
            ('e2', 't1', 'Scan interrupted: the worker was restarted', '2026-10-10 11:00:00'),
            ('e3', 't2', 'nikto timed out', '2026-10-10 11:00:00');
        """
    )

    apply_004_scan_error_message(cursor)
    apply_004_scan_error_message(cursor)  # idempotent

    rows = dict(cursor.execute("SELECT id, error_message FROM scans").fetchall())
    conn.close()
    assert rows["with-reason"] == "Scan interrupted: the worker was restarted"
    assert rows["no-reason"] == "Scan failed (no reason was recorded)"
    assert rows["fine"] is None  # a completed scan has no failure reason
