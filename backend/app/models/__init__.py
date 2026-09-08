"""ORM model registration and prototype table initialization.

Importing this package registers the models below on ``Base.metadata``;
``init_db()`` creates any missing tables from that metadata.
"""

import logging

from sqlalchemy import Engine

from app.core.database import Base, engine

# Import so the Flow table is registered on Base.metadata.
from app.models.flow import Flow  # noqa: F401

__all__ = ["Flow", "init_db"]

logger = logging.getLogger(__name__)


def init_db(bind: Engine | None = None) -> None:
    """Create all registered tables if they don't exist yet (idempotent)."""
    target = bind or engine
    Base.metadata.create_all(bind=target)
    logger.info("Ensured tables: %s", sorted(Base.metadata.tables.keys()))
