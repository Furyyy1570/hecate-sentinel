"""User API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_session
from src.schemas.user import UserCreate, UserListResponse, UserResponse, UserUpdate
from src.services.user import UserService

router = APIRouter(prefix="/users", tags=["users"])


def get_user_service(session: AsyncSession = Depends(get_session)) -> UserService:
    return UserService(session)


@router.get("", response_model=list[UserListResponse])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    service: UserService = Depends(get_user_service),
) -> list[UserListResponse]:
    users = await service.get_all(skip=skip, limit=limit)
    return [UserListResponse.model_validate(u) for u in users]


@router.get("/{user_uuid}", response_model=UserResponse)
async def get_user(
    user_uuid: UUID,
    service: UserService = Depends(get_user_service),
) -> UserResponse:
    user = await service.get_by_uuid(user_uuid)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse.model_validate(user)


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    data: UserCreate,
    service: UserService = Depends(get_user_service),
    session: AsyncSession = Depends(get_session),
) -> UserResponse:
    existing = await service.get_by_username(data.username)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )
    user = await service.create(data)
    await session.commit()
    return UserResponse.model_validate(user)


@router.patch("/{user_uuid}", response_model=UserResponse)
async def update_user(
    user_uuid: UUID,
    data: UserUpdate,
    service: UserService = Depends(get_user_service),
    session: AsyncSession = Depends(get_session),
) -> UserResponse:
    user = await service.get_by_uuid(user_uuid)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if data.username:
        existing = await service.get_by_username(data.username)
        if existing and existing.uuid != user.uuid:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists",
            )

    updated = await service.update(user.id, data)
    await session.commit()
    return UserResponse.model_validate(updated)


@router.delete("/{user_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_uuid: UUID,
    service: UserService = Depends(get_user_service),
    session: AsyncSession = Depends(get_session),
) -> None:
    user = await service.get_by_uuid(user_uuid)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    await service.soft_delete(user.id)
    await session.commit()
