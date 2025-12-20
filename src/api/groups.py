"""Group API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_session
from src.schemas.group import (
    GroupAddPermission,
    GroupAddUser,
    GroupCreate,
    GroupResponse,
    GroupUpdate,
)
from src.schemas.permission import PermissionResponse
from src.schemas.user import UserListResponse
from src.services.group import GroupService

router = APIRouter(prefix="/groups", tags=["groups"])


def get_group_service(session: AsyncSession = Depends(get_session)) -> GroupService:
    return GroupService(session)


@router.get("", response_model=list[GroupResponse])
async def list_groups(
    skip: int = 0,
    limit: int = 100,
    service: GroupService = Depends(get_group_service),
) -> list[GroupResponse]:
    groups = await service.get_all(skip=skip, limit=limit)
    return [GroupResponse.model_validate(g) for g in groups]


@router.get("/{group_uuid}", response_model=GroupResponse)
async def get_group(
    group_uuid: UUID,
    service: GroupService = Depends(get_group_service),
) -> GroupResponse:
    group = await service.get_by_uuid(group_uuid)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    return GroupResponse.model_validate(group)


@router.post("", response_model=GroupResponse, status_code=status.HTTP_201_CREATED)
async def create_group(
    data: GroupCreate,
    service: GroupService = Depends(get_group_service),
    session: AsyncSession = Depends(get_session),
) -> GroupResponse:
    existing = await service.get_by_name(data.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Group name already exists",
        )
    group = await service.create(data)
    await session.commit()
    return GroupResponse.model_validate(group)


@router.patch("/{group_uuid}", response_model=GroupResponse)
async def update_group(
    group_uuid: UUID,
    data: GroupUpdate,
    service: GroupService = Depends(get_group_service),
    session: AsyncSession = Depends(get_session),
) -> GroupResponse:
    group = await service.get_by_uuid(group_uuid)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")

    if data.name:
        existing = await service.get_by_name(data.name)
        if existing and existing.uuid != group.uuid:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Group name already exists",
            )

    updated = await service.update(group.id, data)
    await session.commit()
    return GroupResponse.model_validate(updated)


@router.delete("/{group_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_uuid: UUID,
    service: GroupService = Depends(get_group_service),
    session: AsyncSession = Depends(get_session),
) -> None:
    group = await service.get_by_uuid(group_uuid)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    await service.soft_delete(group.id)
    await session.commit()


# User management
@router.get("/{group_uuid}/users", response_model=list[UserListResponse])
async def list_group_users(
    group_uuid: UUID,
    service: GroupService = Depends(get_group_service),
) -> list[UserListResponse]:
    group = await service.get_with_users_by_uuid(group_uuid)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    return [UserListResponse.model_validate(u) for u in group.users]


@router.post("/{group_uuid}/users", response_model=GroupResponse)
async def add_user_to_group(
    group_uuid: UUID,
    data: GroupAddUser,
    service: GroupService = Depends(get_group_service),
    session: AsyncSession = Depends(get_session),
) -> GroupResponse:
    group = await service.add_user_by_uuid(group_uuid, data.user_uuid)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group or user not found")
    await session.commit()
    return GroupResponse.model_validate(group)


@router.delete("/{group_uuid}/users/{user_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_user_from_group(
    group_uuid: UUID,
    user_uuid: UUID,
    service: GroupService = Depends(get_group_service),
    session: AsyncSession = Depends(get_session),
) -> None:
    group = await service.remove_user_by_uuid(group_uuid, user_uuid)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group or user not found")
    await session.commit()


# Permission management
@router.get("/{group_uuid}/permissions", response_model=list[PermissionResponse])
async def list_group_permissions(
    group_uuid: UUID,
    service: GroupService = Depends(get_group_service),
) -> list[PermissionResponse]:
    group = await service.get_with_permissions_by_uuid(group_uuid)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    return [PermissionResponse.model_validate(p) for p in group.permissions]


@router.post("/{group_uuid}/permissions", response_model=GroupResponse)
async def add_permission_to_group(
    group_uuid: UUID,
    data: GroupAddPermission,
    service: GroupService = Depends(get_group_service),
    session: AsyncSession = Depends(get_session),
) -> GroupResponse:
    group = await service.add_permission_by_uuid(group_uuid, data.permission_uuid)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group or permission not found")
    await session.commit()
    return GroupResponse.model_validate(group)


@router.delete("/{group_uuid}/permissions/{permission_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_permission_from_group(
    group_uuid: UUID,
    permission_uuid: UUID,
    service: GroupService = Depends(get_group_service),
    session: AsyncSession = Depends(get_session),
) -> None:
    group = await service.remove_permission_by_uuid(group_uuid, permission_uuid)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group or permission not found")
    await session.commit()
