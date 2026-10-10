from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict
from datetime import datetime
from typing import Optional
import re

from ..core.security import BCRYPT_MAX_BYTES

# Common weak passwords to reject (top 20 most common)
COMMON_PASSWORDS = {
    'password', 'password1', 'password123', '123456', '12345678', '123456789',
    'qwerty', 'abc123', 'monkey', '1234567', 'letmein', 'trustno1',
    'dragon', 'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
    'admin', 'admin123', 'welcome', 'welcome1', 'p@ssw0rd', 'passw0rd',
}


def validate_password_strength(password: str) -> str:
    """
    Validate password meets security requirements.

    Requirements:
    - At least 8 characters (enforced by Field constraint)
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - Not in common password list
    - No NUL characters, at most 72 bytes in UTF-8 (bcrypt's input limit)
    """
    if '\x00' in password:
        raise ValueError('Password must not contain NUL characters')

    if len(password.encode('utf-8')) > BCRYPT_MAX_BYTES:
        # bcrypt only hashes the first 72 bytes; refuse rather than silently
        # ignore the rest (non-ASCII characters take 2-4 bytes each)
        raise ValueError(f'Password must be at most {BCRYPT_MAX_BYTES} bytes when UTF-8 encoded')

    errors = []

    if not re.search(r'[A-Z]', password):
        errors.append('at least one uppercase letter')

    if not re.search(r'[a-z]', password):
        errors.append('at least one lowercase letter')

    if not re.search(r'[0-9]', password):
        errors.append('at least one digit')

    if password.lower() in COMMON_PASSWORDS:
        raise ValueError('Password is too common. Please choose a stronger password.')

    if errors:
        raise ValueError(f'Password must contain {", ".join(errors)}')

    return password


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    username: str
    is_admin: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)
    is_admin: bool = False

    @field_validator('username')
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username must be alphanumeric (underscores and hyphens allowed)')
        return v

    @field_validator('password')
    @classmethod
    def password_strength(cls, v: str) -> str:
        return validate_password_strength(v)

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    is_admin: Optional[bool] = None
    is_active: Optional[bool] = None

class PasswordReset(BaseModel):
    new_password: str = Field(..., min_length=8, max_length=100)

    @field_validator('new_password')
    @classmethod
    def password_strength(cls, v: str) -> str:
        return validate_password_strength(v)

class UserListResponse(BaseModel):
    users: list[UserResponse]
    total: int
    page: int
    pages: int
