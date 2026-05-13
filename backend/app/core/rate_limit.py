"""
Simple in-memory rate limiting for authentication endpoints.

This implementation uses an in-memory store which is suitable for single-instance
deployments. For multi-instance deployments, consider using Redis-backed rate limiting.
"""

import time
import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Tuple
from fastapi import Request, HTTPException, status

logger = logging.getLogger(__name__)

# Rate limit configuration
LOGIN_RATE_LIMIT = 5  # Max attempts
LOGIN_RATE_WINDOW = 60  # Per 60 seconds


@dataclass
class RateLimitEntry:
    """Track rate limit state for a single key."""
    count: int = 0
    window_start: float = 0.0


class InMemoryRateLimiter:
    """
    Simple in-memory rate limiter using sliding window approach.

    Thread-safe for single process (FastAPI async), but not for multi-process.
    For production multi-instance deployments, use Redis.
    """

    def __init__(self):
        self._store: Dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
        self._cleanup_threshold = 1000  # Cleanup when store exceeds this

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request, considering proxies."""
        # Check X-Forwarded-For header first (reverse proxy scenario)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Take the first IP in the chain (original client)
            return forwarded.split(",")[0].strip()

        # Check X-Real-IP (nginx)
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        # Fall back to direct client IP
        if request.client:
            return request.client.host

        return "unknown"

    def _cleanup_old_entries(self):
        """Remove expired entries to prevent memory growth."""
        if len(self._store) < self._cleanup_threshold:
            return

        current_time = time.time()
        expired_keys = [
            key for key, entry in self._store.items()
            if current_time - entry.window_start > LOGIN_RATE_WINDOW * 2
        ]

        for key in expired_keys:
            del self._store[key]

        if expired_keys:
            logger.debug(f"Rate limiter cleanup: removed {len(expired_keys)} expired entries")

    def check_rate_limit(
        self,
        request: Request,
        limit: int = LOGIN_RATE_LIMIT,
        window: int = LOGIN_RATE_WINDOW
    ) -> Tuple[bool, int, int]:
        """
        Check if request is within rate limit.

        Returns:
            Tuple of (allowed: bool, remaining: int, reset_in: int)
        """
        self._cleanup_old_entries()

        client_ip = self._get_client_ip(request)
        key = f"login:{client_ip}"
        current_time = time.time()

        entry = self._store[key]

        # Check if we're in a new window
        if current_time - entry.window_start > window:
            # Reset the window
            entry.count = 1
            entry.window_start = current_time
            remaining = limit - 1
            reset_in = window
        else:
            # Same window - increment count
            entry.count += 1
            remaining = max(0, limit - entry.count)
            reset_in = int(window - (current_time - entry.window_start))

        allowed = entry.count <= limit

        if not allowed:
            logger.warning(
                f"Rate limit exceeded for {client_ip}: "
                f"{entry.count} attempts in {window}s window"
            )

        return allowed, remaining, reset_in


# Global rate limiter instance
rate_limiter = InMemoryRateLimiter()


async def check_login_rate_limit(request: Request) -> None:
    """
    FastAPI dependency to enforce rate limiting on login endpoint.

    Raises HTTPException with 429 status if rate limit exceeded.
    """
    allowed, remaining, reset_in = rate_limiter.check_rate_limit(request)

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many login attempts. Try again in {reset_in} seconds.",
            headers={
                "Retry-After": str(reset_in),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(reset_in),
            }
        )
