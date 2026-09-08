from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Resolve the .env relative to this file so it works regardless of CWD:
# backend/app/core/.env
_ENV_FILE = Path(__file__).resolve().parent / ".env"


class Settings(BaseSettings):
    """Application settings loaded from backend/app/core/.env."""

    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # PostgreSQL connection string (override via .env / env var)
    DATABASE_URL: str


# Single importable instance
settings = Settings()
