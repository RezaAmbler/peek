from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import text
from .core.config import settings

def get_connect_args():
    """Get connection arguments based on database type"""
    if "sqlite" not in settings.DATABASE_URL:
        return {}
    return {
        "check_same_thread": False,
        "timeout": 30,  # 30 second busy timeout for lock contention
    }

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    connect_args=get_connect_args(),
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

Base = declarative_base()

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def init_db():
    """Initialize database with WAL mode for SQLite"""
    # Import all models to ensure they're registered
    from .models.user import User
    from .models.organization import Organization
    from .models.scan_config import ScanConfig
    from .models.scan import Scan
    from .models.scan_target import ScanTarget
    from .models.tool_execution import ToolExecution
    from .models.port import Port
    from .models.ssh_audit import SSHAudit
    from .models.vulnerability import Vulnerability
    from .models.scan_comparison import ScanComparison
    from .models.scheduled_scan import ScheduledScan
    from .models.nse_finding import NseFinding
    from .models.sslscan_result import SslScanResult
    from .models.httpx_result import HttpxResult

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # Enable WAL mode for SQLite
        if "sqlite" in settings.DATABASE_URL:
            await conn.execute(text("PRAGMA journal_mode=WAL"))
            await conn.execute(text("PRAGMA busy_timeout=30000"))
