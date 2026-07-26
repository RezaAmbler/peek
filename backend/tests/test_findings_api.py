"""
Tests for the triage API (routers/findings.py).

Exercises the async endpoint functions directly against an in-memory async
SQLite session with a stubbed current_user. Covers: PATCH updates status;
invalid status rejected; 404 for an unknown finding.
"""

import uuid
from types import SimpleNamespace

import pytest
import pytest_asyncio

# The triage router imports FastAPI. FastAPI is present in the deployed app but
# not in this service-level test environment; skip the router-level tests when it
# is absent (the status-validation logic is covered fastapi-free in
# test_finding_state_service.py).
pytest.importorskip("fastapi")

from pydantic import ValidationError
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi import HTTPException

from app.database import Base
import app.models  # noqa: F401
from app.models import ScanConfig, FindingState
from app.routers import findings as findings_router
from app.schemas.finding_state import FindingStateUpdate

CONFIG_ID = "config-1"
FP = "a" * 64


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
        # Seed a config owned by user-1 and one finding state.
        session.add(ScanConfig(id=CONFIG_ID, user_id="user-1", name="cfg"))
        session.add(FindingState(
            id=str(uuid.uuid4()), config_id=CONFIG_ID, fingerprint=FP,
            name="CVE-2024-1", status="open",
        ))
        await session.commit()
        yield session
    await engine.dispose()


def _user(uid="user-1", admin=False):
    return SimpleNamespace(id=uid, is_admin=admin)


@pytest.mark.asyncio
async def test_patch_updates_status(adb):
    updated = await findings_router.update_finding_state(
        config_id=CONFIG_ID, fingerprint=FP,
        payload=FindingStateUpdate(status="false_positive", owner="analyst"),
        current_user=_user(), db=adb,
    )
    assert updated.status == "false_positive"
    assert updated.owner == "analyst"


def test_invalid_status_rejected_by_schema():
    with pytest.raises(ValidationError):
        FindingStateUpdate(status="bogus_status")


@pytest.mark.asyncio
async def test_patch_unknown_finding_404(adb):
    with pytest.raises(HTTPException) as exc:
        await findings_router.update_finding_state(
            config_id=CONFIG_ID, fingerprint="f" * 64,
            payload=FindingStateUpdate(status="fixed"),
            current_user=_user(), db=adb,
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_get_finding_state(adb):
    state = await findings_router.get_finding_state(
        config_id=CONFIG_ID, fingerprint=FP, current_user=_user(), db=adb
    )
    assert state.fingerprint == FP


@pytest.mark.asyncio
async def test_list_finding_states_filter(adb):
    rows = await findings_router.list_finding_states(
        config_id=CONFIG_ID, status="open", current_user=_user(), db=adb
    )
    assert len(rows) == 1
    # A status with no rows returns empty.
    rows = await findings_router.list_finding_states(
        config_id=CONFIG_ID, status="fixed", current_user=_user(), db=adb
    )
    assert rows == []


@pytest.mark.asyncio
async def test_list_invalid_status_422(adb):
    with pytest.raises(HTTPException) as exc:
        await findings_router.list_finding_states(
            config_id=CONFIG_ID, status="nope", current_user=_user(), db=adb
        )
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_unauthorized_config_403(adb):
    with pytest.raises(HTTPException) as exc:
        await findings_router.get_finding_state(
            config_id=CONFIG_ID, fingerprint=FP, current_user=_user("other-user"), db=adb
        )
    assert exc.value.status_code == 403
