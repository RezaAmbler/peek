from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import timedelta
from ..database import get_db
from ..models.user import User
from ..schemas.auth import Token, UserResponse
from ..core.security import verify_password, create_access_token, decode_access_token
from ..core.config import settings
from ..core.rate_limit import check_login_rate_limit

# Dummy hash for timing attack prevention
# This is a pre-computed bcrypt hash that we verify against when user doesn't exist
# to ensure constant-time response regardless of whether username is valid
DUMMY_PASSWORD_HASH = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.O/4xJa.r9D8mGi"

router = APIRouter()
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

    **Default credentials**: admin / admin

    Use the returned `access_token` in the Authorization header:
    `Authorization: Bearer <token>`

    Rate limited to 5 attempts per minute per IP address.
    """
    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalar_one_or_none()

    # SECURITY: Always verify password to prevent timing attacks
    # If user doesn't exist, verify against dummy hash to ensure constant-time response
    hash_to_verify = user.hashed_password if user else DUMMY_PASSWORD_HASH
    password_valid = verify_password(form_data.password, hash_to_verify)

    # Check if authentication failed (user doesn't exist OR password invalid)
    if not user or not password_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )

    access_token = create_access_token(data={"sub": str(user.id)})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse.from_orm(user)
    }

@router.get("/me", response_model=UserResponse, summary="Get current user info")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get the currently authenticated user's profile information."""
    return UserResponse.from_orm(current_user)
