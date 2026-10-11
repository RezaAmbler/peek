from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from contextlib import asynccontextmanager
from datetime import datetime
import os
from functools import lru_cache
import secrets
import subprocess
from .core.config import settings
from .database import init_db, AsyncSessionLocal
from .routers import auth, users, configs, scans, comparisons, scheduled_scans, reports, stats, findings
from .core.security import get_password_hash, verify_password
from .schemas.user import validate_password_strength
from .models.user import User
from .models.organization import Organization
from .models.scan_config import ScanConfig
from sqlalchemy import select
from .services.config_service import ensure_user_has_default_config, seed_system_presets

# OpenAPI tag descriptions for Swagger UI grouping
OPENAPI_TAGS = [
    {
        "name": "auth",
        "description": "Authentication endpoints. Login to get a JWT token for accessing protected endpoints."
    },
    {
        "name": "users",
        "description": "User management (admin only). Create, update, and manage user accounts."
    },
    {
        "name": "configs",
        "description": "Scan configuration profiles. Define scanning parameters, timeouts, and tool settings."
    },
    {
        "name": "scans",
        "description": "Create, run, and monitor security scans. View discovered ports, services, and vulnerabilities."
    },
    {
        "name": "scheduled-scans",
        "description": "Automated recurring scans. Schedule scans using cron expressions."
    },
    {
        "name": "comparisons",
        "description": "Compare scan results over time. Identify new ports, closed ports, and vulnerability changes."
    },
    {
        "name": "findings",
        "description": "Triage lifecycle for findings. Set false-positive / accepted-risk / fixed state that persists across scans."
    },
    {
        "name": "reports",
        "description": "Export reports in PDF, HTML, and CSV formats."
    },
]

APP_DESCRIPTION = """
## Network Security Scanner API

PEEK V2 scans networks for open ports, services, and vulnerabilities using:
- **Nmap** - Port discovery and service detection
- **SSH-Audit** - SSH security analysis
- **Nuclei** - Vulnerability scanning

### Authentication
Most endpoints require JWT authentication.
1. Call `POST /api/auth/login` with username/password
2. Copy the `access_token` from response
3. Click the **Authorize** button above and enter: `Bearer <your_token>`

### Quick Start
1. **Login** to get token (the `admin` password comes from `INITIAL_ADMIN_PASSWORD`, or is printed once to the backend log on first start)
2. **Create a scan configuration** (or use default)
3. **Create and start a scan** with target IPs
4. **Monitor progress** and view results

### Scan Workflow
```
POST /api/scans          → Create scan (status: pending)
POST /api/scans/{id}/start → Queue scan (status: queued → running)
GET /api/scans/{id}      → Monitor progress
GET /api/scans/{id}/ports → View discovered ports
GET /api/scans/{id}/vulnerabilities → View vulnerabilities
```
"""

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    apply_migrations_on_startup()
    await create_default_admin()
    # Scans are not touched here: a scan that is running belongs to the Celery
    # worker, which may be perfectly healthy while only the API restarts.
    # Interrupted scans are failed by the worker itself when it starts
    # (celery_app.fail_scans_interrupted_by_restart) and by check_stuck_scans.
    yield
    # Shutdown (if needed)


def apply_migrations_on_startup() -> None:
    """Apply pending SQLite migrations.

    init_db() creates tables from the SQLAlchemy models, but column additions
    on existing tables need ALTER. The custom runner in migrations/ is
    idempotent (schema adds skip if column exists; data wipes are
    sentinel-gated), so calling it every startup is safe.
    """
    try:
        from pathlib import Path
        from migrations.apply_migrations import apply_all

        db_url = settings.DATABASE_URL
        # Strip async driver prefix; runner uses sqlite3 directly.
        if "sqlite+aiosqlite:///" in db_url:
            db_path = db_url.split("sqlite+aiosqlite:///")[1]
        elif "sqlite:///" in db_url:
            db_path = db_url.split("sqlite:///")[1]
        else:
            print(f"⚠️  Skipping migrations: unsupported DATABASE_URL={db_url!r}")
            return

        # Resolve relative paths against the backend working directory.
        if not Path(db_path).is_absolute():
            db_path = str(Path(db_path).resolve())

        apply_all(db_path)
    except Exception as exc:
        print(f"⚠️  Migration runner raised: {exc}")
        raise

def resolve_initial_admin_password() -> tuple[str, bool]:
    """Password for a newly created admin account: (password, was_generated).

    Uses INITIAL_ADMIN_PASSWORD when set, otherwise generates a random one.
    There is no built-in default: PEEK never seeds admin/admin.
    """
    configured = settings.INITIAL_ADMIN_PASSWORD
    if configured:
        try:
            validate_password_strength(configured)
        except ValueError as exc:
            raise RuntimeError(
                f"INITIAL_ADMIN_PASSWORD is not acceptable: {str(exc).rstrip('.')}. "
                "Use at least 8 characters with upper- and lower-case letters and a digit."
            ) from exc
        if len(configured) < 8:
            raise RuntimeError("INITIAL_ADMIN_PASSWORD must be at least 8 characters long.")
        return configured, False
    return secrets.token_urlsafe(18), True


async def create_default_admin():
    """Create the admin user on first start. An existing admin is never modified."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.username == "admin"))
        admin = result.scalar_one_or_none()

        if not admin:
            password, generated = resolve_initial_admin_password()
            admin = User(
                email="admin@example.com",
                username="admin",
                hashed_password=get_password_hash(password),
                is_admin=True,
                is_active=True,
                organization_id=None  # Always NULL in Phase 1-4
            )
            session.add(admin)
            await session.commit()
            await session.refresh(admin)
            if generated:
                # Shown exactly once; it is not stored anywhere in clear text.
                print(
                    "✅ Admin user created (username: admin). INITIAL_ADMIN_PASSWORD was not set, "
                    f"so a random password was generated: {password}\n"
                    "   Log in and change it now (Users -> Reset password); it will not be shown again.\n"
                    "   Treat this log as sensitive until the password has been changed.",
                    flush=True,  # stdout is block-buffered under Docker; this must not sit in a buffer
                )
            else:
                print("✅ Admin user created (username: admin, password from INITIAL_ADMIN_PASSWORD)", flush=True)
        elif verify_password("admin", admin.hashed_password):
            # Deployments created before 2.2.2 were seeded with admin/admin.
            # The account is left untouched, but say so on every start.
            print(
                "⚠️  SECURITY: the 'admin' account still uses the old default password 'admin'. "
                "Change it now (Users -> Reset password).",
                flush=True,
            )

        # Ensure admin has a default config
        await ensure_user_has_default_config(session, admin.id)

        # Seed system presets (owned by admin, visible to all users)
        await seed_system_presets(session, admin.id)

app = FastAPI(
    title="PEEK V2 API",
    description=APP_DESCRIPTION,
    version="2.2.1",
    openapi_tags=OPENAPI_TAGS,
    lifespan=lifespan
)

def custom_openapi():
    """Custom OpenAPI schema with JWT Bearer authentication."""
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=OPENAPI_TAGS,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Enter the JWT token obtained from POST /api/auth/login"
        }
    }
    openapi_schema["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(configs.router, prefix="/api/configs", tags=["configs"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(comparisons.router, prefix="/api/comparisons", tags=["comparisons"])
app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
app.include_router(scheduled_scans.router, prefix="/api/scheduled-scans", tags=["scheduled-scans"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(stats.router, prefix="/api/stats", tags=["stats"])

def _git_output(*args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return ""


def _known(value: str):
    """None for the placeholders a missing git checkout produces."""
    value = (value or "").strip()
    return value if value and value.lower() not in ("unknown", "head") else None


@lru_cache(maxsize=1)
def get_build_info() -> dict:
    """Git branch/commit of the running build (None when not available).

    Deployments have no .git directory (deploy/deploy.sh rsyncs the checkout
    without it), so the deploy script writes GIT_BRANCH / GIT_COMMIT into
    backend/.env. Local development falls back to asking git.
    """
    branch = os.environ.get("GIT_BRANCH") or _git_output("rev-parse", "--abbrev-ref", "HEAD")
    commit = os.environ.get("GIT_COMMIT") or _git_output("rev-parse", "--short", "HEAD")
    return {
        "version": settings.VERSION,
        "git_branch": _known(branch),
        "git_commit": _known(commit),
        "build_time": os.environ.get("BUILD_TIME") or None,
    }


@app.get("/api/health")
async def health_check():
    return {"status": "ok", **get_build_info()}


@app.get("/api/version", summary="Version and build information")
async def version_info():
    return get_build_info()
