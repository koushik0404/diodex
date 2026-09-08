"""CSV -> PostgreSQL ingestion service for DIODEx (Phase 1).

Loads flow records from a CSV via the csv_loader, converts them into
Flow ORM instances, and persists them in a single transaction.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.ingestion.csv_loader import load_flows_from_csv
from app.models.flow import Flow


def ingest_flow_csv(path: str | Path, db: Session | None = None) -> int:
    """Load a flow CSV and insert every record into PostgreSQL.

    Args:
        path: Path to the CSV file (passed straight to load_flows_from_csv).
        db: Optional SQLAlchemy Session. When omitted, the service opens
            (and closes) its own session from SessionLocal.

    Returns:
        The number of records inserted.

    Raises:
        csv_loader.CSVLoaderError: if the CSV is missing/invalid.
        sqlalchemy error: if the insert/commit fails (transaction rolled
            back before re-raising).
    """
    # Parse first: CSV problems fail before we touch any transaction.
    records = load_flows_from_csv(path)
    if not records:
        return 0

    owns_session = db is None
    session = db or SessionLocal()
    try:
        # Flow(**record): loader dict keys match the ORM columns exactly.
        session.add_all(Flow(**record) for record in records)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        if owns_session:
            session.close()

    return len(records)
