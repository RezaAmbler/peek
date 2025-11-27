from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..models.scan_config import ScanConfig

async def create_default_config_for_user(db: AsyncSession, user_id: str) -> ScanConfig:
    """Create a default config for a new user"""
    default_config = ScanConfig(
        user_id=user_id,
        organization_id=None,  # Always NULL in Phase 1-4
        name="Default Configuration",
        description="Standard scanning configuration with balanced settings",
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
