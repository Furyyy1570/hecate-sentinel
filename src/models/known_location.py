"""Known location model for tracking user's recognized login locations."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.user import User


class KnownLocation(Base):
    """Track locations that a user has previously logged in from."""

    __tablename__ = "known_locations"

    id: Mapped[int] = mapped_column(primary_key=True)
    uuid: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), default=uuid4, unique=True, index=True
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    # Location fingerprint (hash of country + city)
    location_fingerprint: Mapped[str] = mapped_column(String(64), index=True)

    # Location info
    country: Mapped[str | None] = mapped_column(String(100), nullable=True)
    country_code: Mapped[str | None] = mapped_column(String(2), nullable=True)
    region: Mapped[str | None] = mapped_column(String(100), nullable=True)
    city: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Timestamps
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    # Trust status
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=True)

    # Relationship
    user: Mapped["User"] = relationship(back_populates="known_locations")
