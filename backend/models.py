
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Owner(Base):
    __tablename__ = "owners"

    owner_id: Mapped[str] = mapped_column(
        String(36), primary_key=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )


class Site(Base):
    __tablename__ = "sites"

    site_id: Mapped[str] = mapped_column(
        String(100), primary_key=True
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    owner_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )


class Alert(Base):
    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(
        String(36), primary_key=True
    )
    schema_version: Mapped[str] = mapped_column(
        String(10), default="1.1", nullable=False
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    window_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    window_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    site_id: Mapped[str | None] = mapped_column(
        String(100), nullable=True, index=True
    )
    owner: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    src_ip: Mapped[str] = mapped_column(
        String(45), nullable=False
    )
    dst_ip: Mapped[str | None] = mapped_column(
        String(45), nullable=True
    )
    dst_port: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    threat_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )
    detected_by: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )
    rule_triggered: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    ml_flag: Mapped[bool | None] = mapped_column(
        Boolean, nullable=True
    )
    anomaly_score: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )

    severity: Mapped[str] = mapped_column(
        String(20), nullable=False
    )
    features: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(20), default="new", nullable=False
    )
