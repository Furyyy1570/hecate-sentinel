"""Service API Key model for service-to-service authentication."""

from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.core.database import Base


class ServiceAPIKey(Base):
    """API keys for trusted services that can call introspection endpoint."""

    __tablename__ = "service_api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # The API key hash (we store hash, not plaintext)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # Key prefix for identification (first 8 chars of the key, e.g., "hsk_abc1...")
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False, index=True)

    # Optional expiration
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Last used tracking
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
