"""OAuth account service."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.oauth_account import OAuthAccount
from src.schemas.oauth_account import OAuthAccountCreate, OAuthAccountUpdate
from src.services.base import BaseService


class OAuthAccountService(BaseService[OAuthAccount, OAuthAccountCreate, OAuthAccountUpdate]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(OAuthAccount, session)

    async def get_by_user(self, user_id: int) -> list[OAuthAccount]:
        result = await self.session.execute(
            select(OAuthAccount).where(OAuthAccount.user_id == user_id)
        )
        return list(result.scalars().all())

    async def get_by_provider(self, provider: str, provider_user_id: str) -> OAuthAccount | None:
        result = await self.session.execute(
            select(OAuthAccount).where(
                OAuthAccount.provider == provider,
                OAuthAccount.provider_user_id == provider_user_id,
            )
        )
        return result.scalar_one_or_none()

    async def create_for_user(self, user_id: int, data: OAuthAccountCreate) -> OAuthAccount:
        oauth = OAuthAccount(
            user_id=user_id,
            provider=data.provider,
            provider_user_id=data.provider_user_id,
            access_token=data.access_token,
            refresh_token=data.refresh_token,
            expires_at=data.expires_at,
        )
        self.session.add(oauth)
        await self.session.flush()
        await self.session.refresh(oauth)
        return oauth
