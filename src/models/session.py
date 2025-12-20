"""User session model for tracking active sessions."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.user import User


class UserSession(Base):
    """Track active user sessions with device and location info."""

    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    uuid: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), default=uuid4, unique=True, index=True
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    # Token identification (hash of refresh token for lookup)
    refresh_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    # Device info
    ip_address: Mapped[str] = mapped_column(String(45))  # IPv6 max length
    user_agent: Mapped[str] = mapped_column(Text)
    device_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    browser: Mapped[str | None] = mapped_column(String(100), nullable=True)
    browser_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    os: Mapped[str | None] = mapped_column(String(100), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    device_brand: Mapped[str | None] = mapped_column(String(100), nullable=True)
    device_model: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Location info (from IP geolocation)
    country: Mapped[str | None] = mapped_column(String(100), nullable=True)
    country_code: Mapped[str | None] = mapped_column(String(2), nullable=True)
    region: Mapped[str | None] = mapped_column(String(100), nullable=True)
    city: Mapped[str | None] = mapped_column(String(100), nullable=True)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    timezone: Mapped[str | None] = mapped_column(String(50), nullable=True)
    isp: Mapped[str | None] = mapped_column(String(200), nullable=True)

    # Session timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_activity_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationship
    user: Mapped["User"] = relationship(back_populates="sessions")
