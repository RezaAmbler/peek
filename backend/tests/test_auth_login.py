"""
Login endpoint and first-start admin seeding.

Covers the end-to-end behaviour the security review asked for: a corrupt stored
hash is a 401 (never a 500), hashes are upgraded on login when the bcrypt cost
changes, and PEEK no longer seeds admin/admin.
"""
from types import SimpleNamespace

import bcrypt
import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app import main as app_main
from app.core.config import settings
from app.core.security import get_password_hash, verify_password
from app.database import Base
import app.models  # noqa: F401
from app.models.user import User
from app.routers import auth as auth_router


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


async def _add_user(session_factory, username, hashed_password, is_active=True):
    async with session_factory() as session:
        user = User(email=f"{username}@example.com", username=username,
                    hashed_password=hashed_password, is_admin=False, is_active=is_active)
        session.add(user)
        await session.commit()
        return user.id


async def _login(session_factory, username, password):
    async with session_factory() as session:
        form = SimpleNamespace(username=username, password=password)
        return await auth_router.login(request=None, form_data=form, db=session, _rate_limit=None)


async def _stored_hash(session_factory, username):
    async with session_factory() as session:
        result = await session.execute(select(User).where(User.username == username))
        return result.scalar_one().hashed_password


# --------------------------------------------------------------------------- login

@pytest.mark.asyncio
async def test_login_success(session_factory):
    await _add_user(session_factory, "alice", get_password_hash("Correct-Horse-1"))

    response = await _login(session_factory, "alice", "Correct-Horse-1")

    assert response["token_type"] == "bearer" and response["access_token"]
    assert response["user"].username == "alice"


@pytest.mark.asyncio
@pytest.mark.parametrize("stored", [
    "$2b$12$xxxxxxxxxx",      # truncated
    "",                       # empty
    "not-a-bcrypt-hash",
    "$2b$99$" + "a" * 53,     # impossible cost
])
async def test_corrupt_stored_hash_is_401_not_500(session_factory, stored):
    await _add_user(session_factory, "broken", stored)

    with pytest.raises(HTTPException) as excinfo:
        await _login(session_factory, "broken", "whatever")

    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "Incorrect username or password"


@pytest.mark.asyncio
@pytest.mark.parametrize("username,password", [
    ("alice", "wrong"),
    ("alice", "Correct-Horse-1\x00"),
    ("alice", "a\x00b"),
    ("alice", "x" * 500),
    ("nobody", "Correct-Horse-1"),
])
async def test_bad_credentials_are_uniform_401(session_factory, username, password):
    await _add_user(session_factory, "alice", get_password_hash("Correct-Horse-1"))

    with pytest.raises(HTTPException) as excinfo:
        await _login(session_factory, username, password)

    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "Incorrect username or password"


@pytest.mark.asyncio
async def test_inactive_user_is_403_only_with_correct_password(session_factory):
    await _add_user(session_factory, "bob", get_password_hash("Correct-Horse-1"), is_active=False)

    with pytest.raises(HTTPException) as excinfo:
        await _login(session_factory, "bob", "Correct-Horse-1")
    assert excinfo.value.status_code == 403

    with pytest.raises(HTTPException) as excinfo:
        await _login(session_factory, "bob", "wrong")
    assert excinfo.value.status_code == 401


@pytest.mark.asyncio
async def test_hash_is_upgraded_on_login_when_cost_differs(session_factory, monkeypatch):
    old_hash = bcrypt.hashpw(b"Correct-Horse-1", bcrypt.gensalt(4)).decode()
    await _add_user(session_factory, "carol", old_hash)
    monkeypatch.setattr(settings, "BCRYPT_ROUNDS", 5)

    # A failed login must not touch the stored hash
    with pytest.raises(HTTPException):
        await _login(session_factory, "carol", "wrong")
    assert await _stored_hash(session_factory, "carol") == old_hash

    await _login(session_factory, "carol", "Correct-Horse-1")

    new_hash = await _stored_hash(session_factory, "carol")
    assert new_hash != old_hash and new_hash.startswith("$2b$05$")
    assert verify_password("Correct-Horse-1", new_hash)

    # Already at the target cost: left alone
    await _login(session_factory, "carol", "Correct-Horse-1")
    assert await _stored_hash(session_factory, "carol") == new_hash


@pytest.mark.asyncio
async def test_rehash_failure_does_not_fail_the_login(session_factory, monkeypatch):
    old_hash = bcrypt.hashpw(b"Correct-Horse-1", bcrypt.gensalt(4)).decode()
    await _add_user(session_factory, "dave", old_hash)
    monkeypatch.setattr(settings, "BCRYPT_ROUNDS", 5)

    def explode(password):
        raise RuntimeError("hashing unavailable")
    monkeypatch.setattr(auth_router, "get_password_hash", explode)

    response = await _login(session_factory, "dave", "Correct-Horse-1")

    assert response["access_token"]
    assert await _stored_hash(session_factory, "dave") == old_hash


# --------------------------------------------------------------------------- admin seeding

@pytest.fixture
def seeding(session_factory, monkeypatch):
    """Run create_default_admin() against the in-memory DB without config seeding."""
    monkeypatch.setattr(app_main, "AsyncSessionLocal", session_factory)

    async def noop(*args, **kwargs):
        return None
    monkeypatch.setattr(app_main, "ensure_user_has_default_config", noop)
    monkeypatch.setattr(app_main, "seed_system_presets", noop)
    return session_factory


@pytest.mark.asyncio
async def test_admin_is_seeded_with_env_password(seeding, monkeypatch, capsys):
    monkeypatch.setattr(settings, "INITIAL_ADMIN_PASSWORD", "Sup3r-Initial-Pass")

    await app_main.create_default_admin()

    stored = await _stored_hash(seeding, "admin")
    assert verify_password("Sup3r-Initial-Pass", stored)
    assert not verify_password("admin", stored)
    assert "Sup3r-Initial-Pass" not in capsys.readouterr().out  # a configured password is never logged


@pytest.mark.asyncio
async def test_admin_gets_random_password_when_env_is_unset(seeding, monkeypatch, capsys):
    monkeypatch.setattr(settings, "INITIAL_ADMIN_PASSWORD", "")

    await app_main.create_default_admin()

    stored = await _stored_hash(seeding, "admin")
    assert not verify_password("admin", stored)
    out = capsys.readouterr().out
    generated = out.split("generated: ")[1].split()[0]
    assert len(generated) >= 20 and verify_password(generated, stored)


@pytest.mark.asyncio
@pytest.mark.parametrize("weak", ["admin", "password", "short1A", "alllowercase1", "NoDigitsHere"])
async def test_weak_initial_admin_password_refuses_to_seed(seeding, monkeypatch, weak):
    monkeypatch.setattr(settings, "INITIAL_ADMIN_PASSWORD", weak)

    with pytest.raises(RuntimeError, match="INITIAL_ADMIN_PASSWORD"):
        await app_main.create_default_admin()

    async with seeding() as session:
        result = await session.execute(select(User).where(User.username == "admin"))
        assert result.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_existing_admin_is_never_modified(seeding, monkeypatch, capsys):
    """Upgrading an existing deployment must not change or lock out its admin."""
    existing_hash = get_password_hash("admin")  # an old default-credential install
    await _add_user(seeding, "admin", existing_hash)
    monkeypatch.setattr(settings, "INITIAL_ADMIN_PASSWORD", "Sup3r-Initial-Pass")

    await app_main.create_default_admin()

    assert await _stored_hash(seeding, "admin") == existing_hash
    assert "still uses the old default password" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_existing_admin_with_changed_password_gets_no_warning(seeding, monkeypatch, capsys):
    existing_hash = get_password_hash("Already-Changed-1")
    await _add_user(seeding, "admin", existing_hash)
    monkeypatch.setattr(settings, "INITIAL_ADMIN_PASSWORD", "")

    await app_main.create_default_admin()

    assert await _stored_hash(seeding, "admin") == existing_hash
    assert capsys.readouterr().out == ""
