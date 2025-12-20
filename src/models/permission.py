"""Permission model."""

from typing import TYPE_CHECKING

from sqlalchemy import Column, ForeignKey, String, Table
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.group import Group

group_permissions = Table(
    "group_permissions",
    Base.metadata,
    Column("group_id", ForeignKey("groups.id"), primary_key=True),
    Column("permission_id", ForeignKey("permissions.id"), primary_key=True),
)


class Permission(Base):
    __tablename__ = "permissions"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)

    groups: Mapped[list["Group"]] = relationship(
        secondary=group_permissions, back_populates="permissions"
    )
