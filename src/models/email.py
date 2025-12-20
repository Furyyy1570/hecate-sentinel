"""Email model."""

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.user import User


class Email(Base):
    __tablename__ = "emails"
    __table_args__ = (
        Index(
            "ix_emails_one_primary_per_user",
            "user_id",
            unique=True,
            postgresql_where="is_primary = true",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    email_address: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped["User"] = relationship(back_populates="emails")
