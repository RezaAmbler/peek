from pydantic_settings import BaseSettings
from typing import List
import secrets

class Settings(BaseSettings):
    # App
    APP_NAME: str = "PEEK V2"
    VERSION: str = "2.0.0"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/peek.db"

    # Auth
    SECRET_KEY: str = "PEEK_SECRET_KEY_DO_NOT_USE_IN_PRODUCTION_CHANGE_THIS_IN_ENV_FILE"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days

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

    # Debug output (saves raw tool output to files when DEBUG=True)
    DEBUG_OUTPUT_DIR: str = "/app/data/debug"  # Inside container, maps to ./data/debug on host

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

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
