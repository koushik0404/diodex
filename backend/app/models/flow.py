from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Flow(Base):
    """One observed network flow entering the DIODEx detection pipeline."""

    __tablename__ = "flows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )

    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)

    source_port: Mapped[int] = mapped_column(Integer, nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)

    protocol: Mapped[str] = mapped_column(String(16), nullable=False)

    packet_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    byte_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    duration: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    def __repr__(self) -> str:  # handy for debugging/logging
        return (
            f"<Flow id={self.id} {self.source_ip}:{self.source_port} -> "
            f"{self.destination_ip}:{self.destination_port} "
            f"proto={self.protocol} ts={self.timestamp}>"
        )
