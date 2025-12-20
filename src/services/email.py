"""Email service."""

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.email import Email
from src.schemas.email import EmailCreate, EmailUpdate
from src.services.base import BaseService


class EmailService(BaseService[Email, EmailCreate, EmailUpdate]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Email, session)

    async def get_by_user(self, user_id: int) -> list[Email]:
        result = await self.session.execute(
            select(Email).where(Email.user_id == user_id)
        )
        return list(result.scalars().all())

    async def get_by_address(self, email_address: str) -> Email | None:
        result = await self.session.execute(
            select(Email).where(Email.email_address == email_address)
        )
        return result.scalar_one_or_none()

    async def create_for_user(self, user_id: int, data: EmailCreate) -> Email:
        email = Email(
            user_id=user_id,
            email_address=data.email_address,
            is_primary=data.is_primary,
            is_verified=data.is_verified,
        )
        self.session.add(email)
        await self.session.flush()
        await self.session.refresh(email)
        return email

    async def set_primary_email(self, user_id: int, email_id: int) -> Email | None:
        """Set an email as primary, unsetting any previous primary for the user."""
        await self.session.execute(
            update(Email)
            .where(Email.user_id == user_id, Email.is_primary == True)
            .values(is_primary=False)
        )

        await self.session.execute(
            update(Email)
            .where(Email.id == email_id, Email.user_id == user_id)
            .values(is_primary=True)
        )

        result = await self.session.execute(
            select(Email).where(Email.id == email_id, Email.user_id == user_id)
        )
        return result.scalar_one_or_none()
