"""User service."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.user import User
from src.schemas.user import UserCreate, UserUpdate
from src.services.base import BaseService


class UserService(BaseService[User, UserCreate, UserUpdate]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(User, session)

    async def get_by_username(self, username: str) -> User | None:
        result = await self.session.execute(
            select(User).where(User.username == username)
        )
        return result.scalar_one_or_none()

    async def create(self, data: UserCreate) -> User:
        user = User(
            username=data.username,
            password=data.password,  # Should be hashed before calling this
            is_admin=data.is_admin,
        )
        self.session.add(user)
        await self.session.flush()
        await self.session.refresh(user)
        return user
