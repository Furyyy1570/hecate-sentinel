"""User model."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.audit_log import AuditLog
    from src.models.email import Email
    from src.models.group import Group
    from src.models.known_device import KnownDevice
    from src.models.known_location import KnownLocation
    from src.models.oauth_account import OAuthAccount
    from src.models.phone import Phone
    from src.models.session import UserSession


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Admin
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)

    # JWT
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Magic links
    magic_link_token: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    magic_link_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # TOTP
    totp_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    # Expiration (for temporary/external users)
    expires_on: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    emails: Mapped[list["Email"]] = relationship(back_populates="user")
    phones: Mapped[list["Phone"]] = relationship(back_populates="user")
    groups: Mapped[list["Group"]] = relationship(
        secondary="user_groups", back_populates="users"
    )
    oauth_accounts: Mapped[list["OAuthAccount"]] = relationship(back_populates="user")
    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    known_devices: Mapped[list["KnownDevice"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    known_locations: Mapped[list["KnownLocation"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="user")
