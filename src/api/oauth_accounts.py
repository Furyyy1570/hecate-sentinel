"""OAuth account API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_session
from src.schemas.oauth_account import (
    OAuthAccountCreate,
    OAuthAccountResponse,
    OAuthAccountUpdate,
)
from src.services.oauth_account import OAuthAccountService
from src.services.user import UserService

router = APIRouter(prefix="/users/{user_uuid}/oauth-accounts", tags=["oauth-accounts"])


def get_oauth_service(session: AsyncSession = Depends(get_session)) -> OAuthAccountService:
    return OAuthAccountService(session)


def get_user_service(session: AsyncSession = Depends(get_session)) -> UserService:
    return UserService(session)


async def get_user_or_404(user_uuid: UUID, user_service: UserService = Depends(get_user_service)):
    user = await user_service.get_by_uuid(user_uuid)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("", response_model=list[OAuthAccountResponse])
async def list_user_oauth_accounts(
    user=Depends(get_user_or_404),
    service: OAuthAccountService = Depends(get_oauth_service),
) -> list[OAuthAccountResponse]:
    accounts = await service.get_by_user(user.id)
    return [OAuthAccountResponse.model_validate(a) for a in accounts]


@router.get("/{oauth_uuid}", response_model=OAuthAccountResponse)
async def get_oauth_account(
    oauth_uuid: UUID,
    user=Depends(get_user_or_404),
    service: OAuthAccountService = Depends(get_oauth_service),
) -> OAuthAccountResponse:
    account = await service.get_by_uuid(oauth_uuid)
    if not account or account.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OAuth account not found")
    return OAuthAccountResponse.model_validate(account)


@router.post("", response_model=OAuthAccountResponse, status_code=status.HTTP_201_CREATED)
async def create_oauth_account(
    data: OAuthAccountCreate,
    user=Depends(get_user_or_404),
    service: OAuthAccountService = Depends(get_oauth_service),
    session: AsyncSession = Depends(get_session),
) -> OAuthAccountResponse:
    existing = await service.get_by_provider(data.provider, data.provider_user_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="OAuth account already linked",
        )
    account = await service.create_for_user(user.id, data)
    await session.commit()
    return OAuthAccountResponse.model_validate(account)


@router.patch("/{oauth_uuid}", response_model=OAuthAccountResponse)
async def update_oauth_account(
    oauth_uuid: UUID,
    data: OAuthAccountUpdate,
    user=Depends(get_user_or_404),
    service: OAuthAccountService = Depends(get_oauth_service),
    session: AsyncSession = Depends(get_session),
) -> OAuthAccountResponse:
    account = await service.get_by_uuid(oauth_uuid)
    if not account or account.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OAuth account not found")

    updated = await service.update(account.id, data)
    await session.commit()
    return OAuthAccountResponse.model_validate(updated)


@router.delete("/{oauth_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_oauth_account(
    oauth_uuid: UUID,
    user=Depends(get_user_or_404),
    service: OAuthAccountService = Depends(get_oauth_service),
    session: AsyncSession = Depends(get_session),
) -> None:
    account = await service.get_by_uuid(oauth_uuid)
    if not account or account.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OAuth account not found")
    await service.soft_delete(account.id)
    await session.commit()
