from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from .core.config import settings
from .database import init_db, AsyncSessionLocal
from .routers import auth, users, configs, scans, comparisons, scheduled_scans, reports
from .core.security import get_password_hash
from .models.user import User
from .models.organization import Organization
from .models.scan_config import ScanConfig
from sqlalchemy import select
from .services.config_service import ensure_user_has_default_config

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    await create_default_admin()
    yield
    # Shutdown (if needed)

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

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    lifespan=lifespan
)

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
