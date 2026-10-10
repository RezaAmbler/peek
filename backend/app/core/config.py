from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from typing import List
import secrets
import os

# Minimum acceptable SECRET_KEY length for security
MIN_SECRET_KEY_LENGTH = 32

# JWTs are HMAC-signed with SECRET_KEY; "none" or asymmetric algorithms would be a misconfiguration
ALLOWED_JWT_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})

class Settings(BaseSettings):
    # App
    APP_NAME: str = "PEEK V2"
    VERSION: str = "2.2.1"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/peek.db"

    # Auth - No default! Must be set in .env or environment
    SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days

    # bcrypt cost factor for new password hashes. Existing hashes with a
    # different cost keep verifying and are upgraded on the next successful login.
    BCRYPT_ROUNDS: int = 12

    # Password for the admin account that is created on first start, when no
    # "admin" user exists yet. Never used again once the account exists.
    # If unset, a random password is generated and printed once to the log.
    INITIAL_ADMIN_PASSWORD: str = ""

    # When the Celery worker starts, scans still marked "running" are failed:
    # they were cut off with the previous worker. Disable only when several
    # workers share one database, where another worker may own the scan.
    FAIL_RUNNING_SCANS_ON_WORKER_START: bool = True

    # CORS
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Celery
    CELERY_BROKER_URL: str = "redis://redis:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/0"

    # Tool paths (can override in .env)
    MASSCAN_PATH: str = "masscan"
    NMAP_PATH: str = "nmap"
    SSH_AUDIT_PATH: str = "ssh-audit"
    NUCLEI_PATH: str = "nuclei"
    HTTPX_PATH: str = "httpx"
    KATANA_PATH: str = "katana"
    # Where nuclei templates are installed; empty = $HOME/nuclei-templates (nuclei's default)
    NUCLEI_TEMPLATES_DIR: str = ""

    # Debug output (saves raw tool output to files when DEBUG=True)
    DEBUG_OUTPUT_DIR: str = "/app/data/debug"  # Inside container, maps to ./data/debug on host

    # Screenshot storage (local filesystem for now, S3-compatible support planned)
    SCREENSHOT_STORAGE_PATH: str = "/app/data/screenshots"  # Inside container, maps to ./data/screenshots on host
    SCREENSHOT_TIMEOUT: int = 10  # Default screenshot capture timeout in seconds

    # Artifact storage for full tool output (when raw_output exceeds truncation limit)
    ARTIFACT_STORAGE_PATH: str = "/app/data/artifacts"  # Inside container, maps to ./data/artifacts on host

    # SMTP Email Configuration
    SMTP_ENABLED: bool = False
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""  # Gmail App Password
    SMTP_FROM_EMAIL: str = "noreply@peek-scanner.local"
    SMTP_FROM_NAME: str = "PEEK Security Scanner"
    SMTP_USE_TLS: bool = True

    # Frontend URL for links in emails
    FRONTEND_URL: str = "http://localhost:3000"

    # Outbound webhook / Slack push (optional). Best-effort: findings leave the
    # tool to a generic webhook and/or a Slack-compatible incoming webhook when a
    # scan produces new critical or KEV-listed findings. Both empty = disabled.
    # requests honors HTTPS_PROXY from the environment automatically.
    WEBHOOK_URL: str = ""        # generic JSON POST endpoint
    SLACK_WEBHOOK_URL: str = ""  # Slack incoming webhook (text/blocks payload)

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",  # Ignore frontend env vars like VITE_API_URL
    )

    @field_validator('BCRYPT_ROUNDS')
    @classmethod
    def validate_bcrypt_rounds(cls, v: int) -> int:
        """bcrypt accepts 4-31. Use 10 or more in production (values above ~16 stall logins).

        Lowering the value never weakens existing hashes: accounts are only
        re-hashed on login when their stored cost is below this setting.
        """
        if not 4 <= v <= 31:
            raise ValueError("BCRYPT_ROUNDS must be between 4 and 31")
        return v

    @field_validator('ALGORITHM')
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        """Only HMAC JWT algorithms: tokens are signed with the shared SECRET_KEY."""
        if v not in ALLOWED_JWT_ALGORITHMS:
            raise ValueError(
                f"ALGORITHM must be one of {sorted(ALLOWED_JWT_ALGORITHMS)} (got {v!r})"
            )
        return v

    @field_validator('SECRET_KEY')
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Validate SECRET_KEY is set and sufficiently strong."""
        # List of known weak/default keys that should never be used.
        # The peek_v2_development_secret_key_... entry is the placeholder
        # that previously lived in docker-compose.yml (removed in Stage 1
        # cleanup). It's blocklisted explicitly so any deployment that
        # somehow reintroduces it fails fast.
        weak_keys = [
            "",
            "PEEK_SECRET_KEY_DO_NOT_USE_IN_PRODUCTION_CHANGE_THIS_IN_ENV_FILE",
            "peek_v2_development_secret_key_change_in_production_12345678901234567890",
            "your-secret-key-here",
            "changeme",
            "secret",
            "password",
        ]

        # Reject the explicit weak list plus any string containing the
        # tell-tale "change_in_production" phrase, regardless of length.
        if v in weak_keys or "change_in_production" in v.lower():
            raise ValueError(
                "SECRET_KEY is not set or uses a weak default. "
                "Generate a secure key with: python -c \"import secrets; print(secrets.token_hex(32))\" "
                "and set it in your backend/.env file."
            )

        if len(v) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(
                f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters. "
                f"Current length: {len(v)}. "
                "Generate a secure key with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        return v

settings = Settings()
