"""Group service."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.models.group import Group
from src.models.permission import Permission
from src.models.user import User
from src.schemas.group import GroupCreate, GroupUpdate
from src.services.base import BaseService


class GroupService(BaseService[Group, GroupCreate, GroupUpdate]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Group, session)

    async def get_by_name(self, name: str) -> Group | None:
        result = await self.session.execute(
            select(Group).where(Group.name == name)
        )
        return result.scalar_one_or_none()

    async def get_with_users(self, id: int) -> Group | None:
        result = await self.session.execute(
            select(Group).options(selectinload(Group.users)).where(Group.id == id)
        )
        return result.scalar_one_or_none()

    async def get_with_users_by_uuid(self, uuid: UUID | str) -> Group | None:
        if isinstance(uuid, str):
            uuid = UUID(uuid)
        result = await self.session.execute(
            select(Group).options(selectinload(Group.users)).where(Group.uuid == uuid)
        )
        return result.scalar_one_or_none()

    async def get_with_permissions(self, id: int) -> Group | None:
        result = await self.session.execute(
            select(Group).options(selectinload(Group.permissions)).where(Group.id == id)
        )
        return result.scalar_one_or_none()

    async def get_with_permissions_by_uuid(self, uuid: UUID | str) -> Group | None:
        if isinstance(uuid, str):
            uuid = UUID(uuid)
        result = await self.session.execute(
            select(Group).options(selectinload(Group.permissions)).where(Group.uuid == uuid)
        )
        return result.scalar_one_or_none()

    async def add_user(self, group_id: int, user_id: int) -> Group | None:
        group = await self.get_with_users(group_id)
        if not group:
            return None

        user_result = await self.session.execute(
            select(User).where(User.id == user_id)
        )
        user = user_result.scalar_one_or_none()
        if not user:
            return None

        if user not in group.users:
            group.users.append(user)
            await self.session.flush()

        return group

    async def add_user_by_uuid(self, group_uuid: UUID | str, user_uuid: UUID | str) -> Group | None:
        group = await self.get_with_users_by_uuid(group_uuid)
        if not group:
            return None

        if isinstance(user_uuid, str):
            user_uuid = UUID(user_uuid)
        user_result = await self.session.execute(
            select(User).where(User.uuid == user_uuid)
        )
        user = user_result.scalar_one_or_none()
        if not user:
            return None

        if user not in group.users:
            group.users.append(user)
            await self.session.flush()

        return group

    async def remove_user(self, group_id: int, user_id: int) -> Group | None:
        group = await self.get_with_users(group_id)
        if not group:
            return None

        user_result = await self.session.execute(
            select(User).where(User.id == user_id)
        )
        user = user_result.scalar_one_or_none()
        if not user:
            return None

        if user in group.users:
            group.users.remove(user)
            await self.session.flush()

        return group

    async def remove_user_by_uuid(self, group_uuid: UUID | str, user_uuid: UUID | str) -> Group | None:
        group = await self.get_with_users_by_uuid(group_uuid)
        if not group:
            return None

        if isinstance(user_uuid, str):
            user_uuid = UUID(user_uuid)
        user_result = await self.session.execute(
            select(User).where(User.uuid == user_uuid)
        )
        user = user_result.scalar_one_or_none()
        if not user:
            return None

        if user in group.users:
            group.users.remove(user)
            await self.session.flush()

        return group

    async def add_permission(self, group_id: int, permission_id: int) -> Group | None:
        group = await self.get_with_permissions(group_id)
        if not group:
            return None

        perm_result = await self.session.execute(
            select(Permission).where(Permission.id == permission_id)
        )
        permission = perm_result.scalar_one_or_none()
        if not permission:
            return None

        if permission not in group.permissions:
            group.permissions.append(permission)
            await self.session.flush()

        return group

    async def add_permission_by_uuid(self, group_uuid: UUID | str, permission_uuid: UUID | str) -> Group | None:
        group = await self.get_with_permissions_by_uuid(group_uuid)
        if not group:
            return None

        if isinstance(permission_uuid, str):
            permission_uuid = UUID(permission_uuid)
        perm_result = await self.session.execute(
            select(Permission).where(Permission.uuid == permission_uuid)
        )
        permission = perm_result.scalar_one_or_none()
        if not permission:
            return None

        if permission not in group.permissions:
            group.permissions.append(permission)
            await self.session.flush()

        return group

    async def remove_permission(self, group_id: int, permission_id: int) -> Group | None:
        group = await self.get_with_permissions(group_id)
        if not group:
            return None

        perm_result = await self.session.execute(
            select(Permission).where(Permission.id == permission_id)
        )
        permission = perm_result.scalar_one_or_none()
        if not permission:
            return None

        if permission in group.permissions:
            group.permissions.remove(permission)
            await self.session.flush()

        return group

    async def remove_permission_by_uuid(self, group_uuid: UUID | str, permission_uuid: UUID | str) -> Group | None:
        group = await self.get_with_permissions_by_uuid(group_uuid)
        if not group:
            return None

        if isinstance(permission_uuid, str):
            permission_uuid = UUID(permission_uuid)
        perm_result = await self.session.execute(
            select(Permission).where(Permission.uuid == permission_uuid)
        )
        permission = perm_result.scalar_one_or_none()
        if not permission:
            return None

        if permission in group.permissions:
            group.permissions.remove(permission)
            await self.session.flush()

        return group
