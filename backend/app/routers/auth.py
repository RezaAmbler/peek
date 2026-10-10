from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from datetime import timedelta
import logging
import secrets
from ..database import get_db
from ..models.user import User
from ..schemas.auth import Token, UserResponse
from ..core.security import (
    verify_password, create_access_token, decode_access_token,
    get_password_hash, password_needs_rehash, is_usable_password_hash,
)
from ..core.config import settings
from ..core.rate_limit import check_login_rate_limit

# Dummy hash for timing attack prevention
# Verified against when the user doesn't exist (or has an unusable stored hash)
# so those requests cost one full bcrypt verification like any other. Generated
# at import with the configured cost, from a random value nobody knows.
DUMMY_PASSWORD_HASH = get_password_hash(secrets.token_urlsafe(32))

router = APIRouter()
logger = logging.getLogger(__name__)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )

    return user

@router.post("/login", response_model=Token, summary="Login and get JWT token")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
    _rate_limit: None = Depends(check_login_rate_limit)
):
    """
    Authenticate user and return a JWT access token.

    The `admin` account is created on first start with the password from
    `INITIAL_ADMIN_PASSWORD` (or a random one printed once to the backend log).

    Use the returned `access_token` in the Authorization header:
    `Authorization: Bearer <token>`

    Rate limited to 5 attempts per minute per IP address.
    """
    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalar_one_or_none()

    # SECURITY: Always verify password to prevent timing attacks
    # If user doesn't exist, verify against dummy hash to ensure constant-time response
    # A corrupt stored hash takes the same path as an unknown user.
    has_usable_hash = bool(user) and is_usable_password_hash(user.hashed_password)
    hash_to_verify = user.hashed_password if has_usable_hash else DUMMY_PASSWORD_HASH
    password_valid = verify_password(form_data.password, hash_to_verify)

    # Check if authentication failed (user doesn't exist OR password invalid)
    if not user or not has_usable_hash or not password_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )

    # Upgrade the stored hash when its bcrypt cost differs from BCRYPT_ROUNDS
    # (or it uses a legacy variant). Best-effort: it must never fail a login.
    if password_needs_rehash(user.hashed_password):
        try:
            # Compare-and-set on the hash we just verified: if the password was
            # changed meanwhile (e.g. an admin reset), this updates nothing
            # instead of writing the old password back.
            verified_hash = user.hashed_password
            await db.execute(
                update(User)
                .where(User.id == user.id, User.hashed_password == verified_hash)
                .values(hashed_password=get_password_hash(form_data.password))
            )
            await db.commit()
            await db.refresh(user)
        except Exception as exc:
            logger.warning(f"Password rehash failed for user {user.id}: {exc}")
            await db.rollback()
            await db.refresh(user)

    access_token = create_access_token(data={"sub": str(user.id)})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse.model_validate(user)
    }

@router.get("/me", response_model=UserResponse, summary="Get current user info")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get the currently authenticated user's profile information."""
    return UserResponse.model_validate(current_user)
