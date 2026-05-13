import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..models.scan_config import ScanConfig


logger = logging.getLogger(__name__)

# Timeout values must match scan_mode constraints:
# - deep mode: 1440s - 6840s (center: 3600s / 1 hour)
# - fast mode: 480s - 2280s (center: 1200s / 20 min)
SYSTEM_PRESETS = [
    {
        "name": "Deep Scan (Full Coverage)",
        "description": "Comprehensive scan of all 65,535 TCP ports with all security tools enabled. Best for thorough assessments.",
        "scan_mode": "deep",
        "host_timeout_seconds": 3600,  # 1 hour - center value for deep mode
        "enable_nuclei": True,
        "enable_ssh_audit": True,
        "enable_nikto": True,
        "enable_zap": True,
        "enable_nse": True,
        "enable_sslscan": True,
        "enable_httpx": True,
        "enable_katana": True,
        "enable_testssl": True,
        "enable_nuclei_endpoints": True,
        "is_preset": True,
    },
    {
        "name": "Fast Scan (Quick Assessment)",
        "description": "Quick scan of top 1000 ports plus common services. Good for initial reconnaissance or time-limited scans.",
        "scan_mode": "fast",
        "host_timeout_seconds": 1200,  # 20 min - center value for fast mode
        "enable_nuclei": True,
        "enable_ssh_audit": True,
        "enable_nikto": False,  # Disabled for speed
        "enable_zap": False,    # Disabled for speed
        "enable_nse": True,
        "enable_sslscan": True,
        "enable_httpx": True,
        "enable_katana": False,           # Disabled for speed
        "enable_testssl": False,          # Disabled for speed
        "enable_nuclei_endpoints": False, # Disabled for speed
        "is_preset": True,
    },
]

async def seed_system_presets(db: AsyncSession, admin_user_id: str) -> None:
    """Create system preset configurations if they don't exist"""
    result = await db.execute(
        select(ScanConfig).where(ScanConfig.is_preset == True)
    )
    existing_presets = result.scalars().all()
    existing_names = {p.name for p in existing_presets}

    for preset_data in SYSTEM_PRESETS:
        if preset_data["name"] not in existing_names:
            preset = ScanConfig(
                user_id=admin_user_id,
                organization_id=None,
                is_default=False,
                **preset_data
            )
            db.add(preset)
            logger.info("Created system preset: %s", preset_data["name"])

    await db.commit()

async def create_default_config_for_user(db: AsyncSession, user_id: str) -> ScanConfig:
    """Create a default config for a new user"""
    # Default scan_mode is 'deep', so use valid timeout for deep mode (3600s)
    default_config = ScanConfig(
        user_id=user_id,
        organization_id=None,  # Always NULL in Phase 1-4
        name="Default Configuration",
        description="Standard scanning configuration with balanced settings",
        host_timeout_seconds=3600,  # Valid for default 'deep' mode
        is_default=True
    )
    db.add(default_config)
    await db.commit()
    await db.refresh(default_config)
    return default_config

async def ensure_user_has_default_config(db: AsyncSession, user_id: str) -> None:
    """Ensure user has at least one default config"""
    result = await db.execute(
        select(ScanConfig).where(ScanConfig.user_id == user_id)
    )
    configs = result.scalars().all()

    if not configs:
        # Create default config
        await create_default_config_for_user(db, user_id)
    elif not any(c.is_default for c in configs):
        # Set first config as default
        configs[0].is_default = True
        await db.commit()
