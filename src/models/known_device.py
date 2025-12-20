"""Known device model for tracking user's recognized devices."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.user import User


class KnownDevice(Base):
    """Track devices that a user has previously logged in from."""

    __tablename__ = "known_devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    uuid: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), default=uuid4, unique=True, index=True
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    # Device fingerprint (hash of user_agent + normalized browser info)
    device_fingerprint: Mapped[str] = mapped_column(String(64), index=True)

    # Device info (for display)
    user_agent: Mapped[str] = mapped_column(Text)
    device_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    browser: Mapped[str | None] = mapped_column(String(100), nullable=True)
    os: Mapped[str | None] = mapped_column(String(100), nullable=True)
    device_brand: Mapped[str | None] = mapped_column(String(100), nullable=True)
    device_model: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Device naming
    friendly_name: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Timestamps
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    # Trust status
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=True)

    # Relationship
    user: Mapped["User"] = relationship(back_populates="known_devices")
