"""Phone model."""

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.user import User


class Phone(Base):
    __tablename__ = "phones"
    __table_args__ = (
        Index(
            "ix_phones_one_primary_per_user",
            "user_id",
            unique=True,
            postgresql_where="is_primary = true",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    phone_number: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped["User"] = relationship(back_populates="phones")
