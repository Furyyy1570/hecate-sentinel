"""Security audit log model."""

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.user import User


class AuditEventType(str, Enum):
    """Types of security events to audit."""

    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGIN_BLOCKED = "login_blocked"
    LOGOUT = "logout"
    LOGOUT_ALL = "logout_all"

    # Token events
    TOKEN_REFRESH = "token_refresh"
    TOKEN_REVOKED = "token_revoked"

    # Session events
    SESSION_CREATED = "session_created"
    SESSION_REVOKED = "session_revoked"

    # Password events
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET_REQUESTED = "password_reset_requested"
    PASSWORD_RESET_COMPLETED = "password_reset_completed"

    # TOTP events
    TOTP_ENABLED = "totp_enabled"
    TOTP_DISABLED = "totp_disabled"
    TOTP_VERIFIED = "totp_verified"
    TOTP_FAILED = "totp_failed"
    RECOVERY_CODE_USED = "recovery_code_used"
    RECOVERY_CODES_REGENERATED = "recovery_codes_regenerated"

    # Email events
    EMAIL_VERIFIED = "email_verified"
    EMAIL_VERIFICATION_REQUESTED = "email_verification_requested"

    # Device/Location events
    NEW_DEVICE_LOGIN = "new_device_login"
    NEW_LOCATION_LOGIN = "new_location_login"
    DEVICE_TRUSTED = "device_trusted"
    DEVICE_UNTRUSTED = "device_untrusted"

    # OAuth events
    OAUTH_LOGIN = "oauth_login"
    OAUTH_ACCOUNT_LINKED = "oauth_account_linked"
    OAUTH_ACCOUNT_UNLINKED = "oauth_account_unlinked"

    # Account events
    ACCOUNT_CREATED = "account_created"
    ACCOUNT_DELETED = "account_deleted"


class AuditLog(Base):
    """Security audit log for tracking all security-relevant events."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    uuid: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), default=uuid4, unique=True, index=True
    )

    # User reference (nullable for failed logins with unknown user)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )

    # Event details
    event_type: Mapped[AuditEventType] = mapped_column(
        SQLEnum(AuditEventType, name="audit_event_type"), index=True
    )
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )

    # Request context
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Location context (optional, populated if available)
    country: Mapped[str | None] = mapped_column(String(100), nullable=True)
    city: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Event-specific data (JSON)
    event_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Success/failure indicator
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    failure_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Session reference (if applicable)
    session_id: Mapped[int | None] = mapped_column(
        ForeignKey("user_sessions.id"), nullable=True
    )

    # Relationship
    user: Mapped["User | None"] = relationship(back_populates="audit_logs")
