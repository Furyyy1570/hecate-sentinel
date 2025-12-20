"""Phone service."""

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.phone import Phone
from src.schemas.phone import PhoneCreate, PhoneUpdate
from src.services.base import BaseService


class PhoneService(BaseService[Phone, PhoneCreate, PhoneUpdate]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Phone, session)

    async def get_by_user(self, user_id: int) -> list[Phone]:
        result = await self.session.execute(
            select(Phone).where(Phone.user_id == user_id)
        )
        return list(result.scalars().all())

    async def get_by_number(self, phone_number: str) -> Phone | None:
        result = await self.session.execute(
            select(Phone).where(Phone.phone_number == phone_number)
        )
        return result.scalar_one_or_none()

    async def create_for_user(self, user_id: int, data: PhoneCreate) -> Phone:
        phone = Phone(
            user_id=user_id,
            phone_number=data.phone_number,
            is_primary=data.is_primary,
            is_verified=data.is_verified,
        )
        self.session.add(phone)
        await self.session.flush()
        await self.session.refresh(phone)
        return phone

    async def set_primary_phone(self, user_id: int, phone_id: int) -> Phone | None:
        """Set a phone as primary, unsetting any previous primary for the user."""
        await self.session.execute(
            update(Phone)
            .where(Phone.user_id == user_id, Phone.is_primary == True)
            .values(is_primary=False)
        )

        await self.session.execute(
            update(Phone)
            .where(Phone.id == phone_id, Phone.user_id == user_id)
            .values(is_primary=True)
        )

        result = await self.session.execute(
            select(Phone).where(Phone.id == phone_id, Phone.user_id == user_id)
        )
        return result.scalar_one_or_none()
