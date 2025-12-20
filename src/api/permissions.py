"""Permission API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_session
from src.schemas.permission import PermissionCreate, PermissionResponse, PermissionUpdate
from src.services.permission import PermissionService

router = APIRouter(prefix="/permissions", tags=["permissions"])


def get_permission_service(session: AsyncSession = Depends(get_session)) -> PermissionService:
    return PermissionService(session)


@router.get("", response_model=list[PermissionResponse])
async def list_permissions(
    skip: int = 0,
    limit: int = 100,
    service: PermissionService = Depends(get_permission_service),
) -> list[PermissionResponse]:
    permissions = await service.get_all(skip=skip, limit=limit)
    return [PermissionResponse.model_validate(p) for p in permissions]


@router.get("/{permission_uuid}", response_model=PermissionResponse)
async def get_permission(
    permission_uuid: UUID,
    service: PermissionService = Depends(get_permission_service),
) -> PermissionResponse:
    permission = await service.get_by_uuid(permission_uuid)
    if not permission:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found")
    return PermissionResponse.model_validate(permission)


@router.post("", response_model=PermissionResponse, status_code=status.HTTP_201_CREATED)
async def create_permission(
    data: PermissionCreate,
    service: PermissionService = Depends(get_permission_service),
    session: AsyncSession = Depends(get_session),
) -> PermissionResponse:
    existing = await service.get_by_name(data.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Permission name already exists",
        )
    permission = await service.create(data)
    await session.commit()
    return PermissionResponse.model_validate(permission)


@router.patch("/{permission_uuid}", response_model=PermissionResponse)
async def update_permission(
    permission_uuid: UUID,
    data: PermissionUpdate,
    service: PermissionService = Depends(get_permission_service),
    session: AsyncSession = Depends(get_session),
) -> PermissionResponse:
    permission = await service.get_by_uuid(permission_uuid)
    if not permission:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found")

    if data.name:
        existing = await service.get_by_name(data.name)
        if existing and existing.uuid != permission.uuid:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Permission name already exists",
            )

    updated = await service.update(permission.id, data)
    await session.commit()
    return PermissionResponse.model_validate(updated)


@router.delete("/{permission_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_permission(
    permission_uuid: UUID,
    service: PermissionService = Depends(get_permission_service),
    session: AsyncSession = Depends(get_session),
) -> None:
    permission = await service.get_by_uuid(permission_uuid)
    if not permission:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found")
    await service.soft_delete(permission.id)
    await session.commit()
