"""Permission service."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.permission import Permission
from src.schemas.permission import PermissionCreate, PermissionUpdate
from src.services.base import BaseService


class PermissionService(BaseService[Permission, PermissionCreate, PermissionUpdate]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Permission, session)

    async def get_by_name(self, name: str) -> Permission | None:
        result = await self.session.execute(
            select(Permission).where(Permission.name == name)
        )
        return result.scalar_one_or_none()
