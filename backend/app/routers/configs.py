from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from typing import Optional
from ..database import get_db
from ..models.scan_config import ScanConfig
from ..models.user import User
from ..schemas.scan_config import (
    ScanConfigCreate,
    ScanConfigUpdate,
    ScanConfigResponse,
    ScanConfigListResponse
)
from ..routers.auth import get_current_user

router = APIRouter()

async def get_config_by_id(
    config_id: str,
    current_user: User,
    db: AsyncSession
) -> ScanConfig:
    """Helper to get config and verify ownership"""
    result = await db.execute(
        select(ScanConfig).where(ScanConfig.id == config_id)
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Configuration not found"
        )

    # Authorization: owner or admin
    if config.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this configuration"
        )

    return config

@router.get("", response_model=ScanConfigListResponse, summary="List configurations")
async def list_configs(
    user_id: Optional[str] = Query(None, description="Filter by user ID (admin only)"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List all scan configurations for the current user."""
    # Determine which user's configs to fetch
    if user_id:
        # Admin can view other users' configs
        if not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can view other users' configurations"
            )
        target_user_id = user_id
    else:
        target_user_id = current_user.id

    # Fetch configs
    result = await db.execute(
        select(ScanConfig)
        .where(ScanConfig.user_id == target_user_id)
        .order_by(ScanConfig.is_default.desc(), ScanConfig.created_at.desc())
    )
    configs = result.scalars().all()

    return ScanConfigListResponse(
        configs=configs,
        total=len(configs)
    )

@router.get("/{config_id}", response_model=ScanConfigResponse)
async def get_config(
    config_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get a single configuration by ID"""
    config = await get_config_by_id(config_id, current_user, db)
    return config

@router.post("", response_model=ScanConfigResponse, status_code=status.HTTP_201_CREATED, summary="Create configuration")
async def create_config(
    config_data: ScanConfigCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new scan configuration profile.

    Configurations define scan parameters like masscan rate, nmap arguments, and Nuclei settings.
    """
    # Check if user has any configs (if not, make this the default)
    result = await db.execute(
        select(ScanConfig).where(ScanConfig.user_id == current_user.id)
    )
    existing_configs = result.scalars().all()
    is_first_config = len(existing_configs) == 0

    # Create config
    new_config = ScanConfig(
        **config_data.model_dump(),
        user_id=current_user.id,
        organization_id=None,  # Always NULL in Phase 1-4
        is_default=is_first_config
    )

    db.add(new_config)
    await db.commit()
    await db.refresh(new_config)

    return new_config

@router.patch("/{config_id}", response_model=ScanConfigResponse)
async def update_config(
    config_id: str,
    config_data: ScanConfigUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update an existing configuration"""
    config = await get_config_by_id(config_id, current_user, db)

    # Update fields
    update_data = config_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(config, field, value)

    await db.commit()
    await db.refresh(config)

    return config

@router.delete("/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_config(
    config_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete a configuration"""
    config = await get_config_by_id(config_id, current_user, db)

    was_default = config.is_default

    # Delete config
    await db.delete(config)
    await db.commit()

    # If deleted config was default, set another as default
    if was_default:
        result = await db.execute(
            select(ScanConfig)
            .where(ScanConfig.user_id == current_user.id)
            .order_by(ScanConfig.created_at.desc())
            .limit(1)
        )
        remaining_config = result.scalar_one_or_none()

        if remaining_config:
            remaining_config.is_default = True
            await db.commit()

    return None

@router.post("/{config_id}/set-default", response_model=ScanConfigResponse)
async def set_default_config(
    config_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Set a configuration as the default for the user"""
    config = await get_config_by_id(config_id, current_user, db)

    # Only owner can set their own default (not admin)
    if config.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only set your own configurations as default"
        )

    # Unset all other defaults for this user
    result = await db.execute(
        select(ScanConfig).where(
            and_(
                ScanConfig.user_id == current_user.id,
                ScanConfig.is_default == True
            )
        )
    )
    for existing_default in result.scalars().all():
        existing_default.is_default = False

    # Set this as default
    config.is_default = True

    await db.commit()
    await db.refresh(config)

    return config
