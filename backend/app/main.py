from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from contextlib import asynccontextmanager
from datetime import datetime
from .core.config import settings
from .database import init_db, AsyncSessionLocal
from .routers import auth, users, configs, scans, comparisons, scheduled_scans, reports
from .core.security import get_password_hash
from .models.user import User
from .models.organization import Organization
from .models.scan_config import ScanConfig
from .models.scan import Scan, ScanStatus
from sqlalchemy import select, or_
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
1. **Login** to get token (default: admin/admin)
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
    await create_default_admin()
    await cleanup_orphaned_scans()
    yield
    # Shutdown (if needed)

async def cleanup_orphaned_scans():
    """Mark any running/queued scans as cancelled on startup.

    These are orphaned scans from a previous run where the worker was killed.
    """
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Scan).where(
                or_(
                    Scan.status == ScanStatus.RUNNING.value,
                    Scan.status == ScanStatus.QUEUED.value
                )
            )
        )
        orphaned_scans = result.scalars().all()

        if orphaned_scans:
            for scan in orphaned_scans:
                scan.status = ScanStatus.CANCELLED.value
                scan.finished_at = datetime.utcnow()
            await session.commit()
            print(f"⚠️  Marked {len(orphaned_scans)} orphaned scan(s) as cancelled")

async def create_default_admin():
    """Create default admin user if it doesn't exist"""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.username == "admin"))
        admin = result.scalar_one_or_none()

        if not admin:
            admin = User(
                email="admin@example.com",
                username="admin",
                hashed_password=get_password_hash("admin"),
                is_admin=True,
                is_active=True,
                organization_id=None  # Always NULL in Phase 1-4
            )
            session.add(admin)
            await session.commit()
            await session.refresh(admin)
            print("✅ Default admin user created (username: admin, password: admin)")

        # Ensure admin has a default config
        await ensure_user_has_default_config(session, admin.id)

        # Seed system presets (owned by admin, visible to all users)
        await seed_system_presets(session, admin.id)

app = FastAPI(
    title="PEEK V2 API",
    description=APP_DESCRIPTION,
    version="2.0.0",
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
app.include_router(scheduled_scans.router, prefix="/api/scheduled-scans", tags=["scheduled-scans"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "version": settings.VERSION}
