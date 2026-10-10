import logging
import re
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
import bcrypt
from .config import settings
from .timeutil import utcnow

logger = logging.getLogger(__name__)

# bcrypt hashes at most 72 bytes of input. passlib used to truncate silently;
# bcrypt>=5 raises instead, so truncate explicitly to keep existing hashes
# (and long passwords) verifying exactly as before.
#
# New and reset passwords are rejected by the API when they exceed 72 bytes
# (see schemas.user.validate_password_strength), so nothing is silently ignored
# going forward. Truncation only still matters for callers that bypass the
# schema and for hashes created before that rule existed.
BCRYPT_MAX_BYTES = 72

# Modular-crypt bcrypt hash: $2<a|b|x|y>$<2-digit cost>$<22-char salt><31-char digest>
_BCRYPT_HASH_RE = re.compile(r"^\$2[abxy]\$(\d{2})\$[./A-Za-z0-9]{53}$")


def _encode(password: str) -> bytes:
    """UTF-8 encode, cut to bcrypt's 72 bytes without splitting a character."""
    encoded = password.encode("utf-8")
    if len(encoded) <= BCRYPT_MAX_BYTES:
        return encoded
    end = BCRYPT_MAX_BYTES
    # 0b10xxxxxx is a UTF-8 continuation byte: byte `end` being one means the
    # cut would land inside a multi-byte character, so back up to its start.
    while end > 0 and (encoded[end] & 0xC0) == 0x80:
        end -= 1
    return encoded[:end]


def _encode_legacy(password: str) -> bytes:
    """Byte-exact truncation as done by passlib and PEEK <= 2.2.1 (may split a character)."""
    return password.encode("utf-8")[:BCRYPT_MAX_BYTES]


def _hash_cost(hashed_password: str) -> Optional[int]:
    """Cost factor of a well-formed bcrypt hash, else None."""
    if not isinstance(hashed_password, str):
        return None
    match = _BCRYPT_HASH_RE.match(hashed_password)
    return int(match.group(1)) if match else None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check a password against a stored bcrypt hash.

    Never raises: a missing, malformed, truncated or otherwise unusable stored
    hash (or an un-encodable password) is a failed login, not a 500.
    """
    if not isinstance(plain_password, str) or _hash_cost(hashed_password) is None:
        # Shape check first: older bcrypt builds panic (pyo3 PanicException,
        # a BaseException) instead of raising ValueError on truncated hashes.
        return False
    try:
        hashed = hashed_password.encode("ascii")
        candidates = [_encode(plain_password)]
        legacy = _encode_legacy(plain_password)
        if legacy != candidates[0]:
            # Hash may predate character-boundary truncation
            candidates.append(legacy)
        return any(bcrypt.checkpw(candidate, hashed) for candidate in candidates)
    except Exception:
        # bcrypt raises ValueError ("Invalid salt") for hashes it cannot parse,
        # e.g. an out-of-range cost; encoding errors land here too.
        return False
    except BaseException as exc:  # pragma: no cover - depends on bcrypt build
        if type(exc).__name__ == "PanicException":
            logger.error("bcrypt panicked while verifying a stored hash; treating as mismatch")
            return False
        raise


def get_password_hash(password: str) -> str:
    """Hash a password with bcrypt at the configured cost (settings.BCRYPT_ROUNDS)."""
    salt = bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS)
    return bcrypt.hashpw(_encode(password), salt).decode("utf-8")


def password_needs_rehash(hashed_password: str) -> bool:
    """True if a (valid) stored hash should be re-hashed after a successful login.

    That is the case when its cost differs from settings.BCRYPT_ROUNDS or it
    uses a legacy bcrypt variant ($2a$/$2x$/$2y$) instead of $2b$.
    """
    cost = _hash_cost(hashed_password)
    if cost is None:
        return False
    return cost != settings.BCRYPT_ROUNDS or not hashed_password.startswith("$2b$")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = utcnow() + expires_delta
    else:
        expire = utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        return None
