"""Group model."""

from typing import TYPE_CHECKING

from sqlalchemy import Column, ForeignKey, String, Table
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.permission import Permission
    from src.models.user import User

user_groups = Table(
    "user_groups",
    Base.metadata,
    Column("user_id", ForeignKey("users.id"), primary_key=True),
    Column("group_id", ForeignKey("groups.id"), primary_key=True),
)


class Group(Base):
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)

    users: Mapped[list["User"]] = relationship(
        secondary=user_groups, back_populates="groups"
    )
    permissions: Mapped[list["Permission"]] = relationship(
        secondary="group_permissions", back_populates="groups"
    )
