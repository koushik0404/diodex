from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings

# SQLAlchemy engine backed by the DATABASE_URL from config (backend/app/core/.env)
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
)

# Session factory: one session per request, managed by the get_db dependency
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Declarative base class for all ORM models."""


def get_db() -> "Session":
    """FastAPI dependency yielding a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
