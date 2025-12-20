"""Phone API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_session
from src.schemas.phone import PhoneCreate, PhoneResponse, PhoneUpdate
from src.services.phone import PhoneService
from src.services.user import UserService

router = APIRouter(prefix="/users/{user_uuid}/phones", tags=["phones"])


def get_phone_service(session: AsyncSession = Depends(get_session)) -> PhoneService:
    return PhoneService(session)


def get_user_service(session: AsyncSession = Depends(get_session)) -> UserService:
    return UserService(session)


async def get_user_or_404(user_uuid: UUID, user_service: UserService = Depends(get_user_service)):
    user = await user_service.get_by_uuid(user_uuid)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("", response_model=list[PhoneResponse])
async def list_user_phones(
    user=Depends(get_user_or_404),
    service: PhoneService = Depends(get_phone_service),
) -> list[PhoneResponse]:
    phones = await service.get_by_user(user.id)
    return [PhoneResponse.model_validate(p) for p in phones]


@router.get("/{phone_uuid}", response_model=PhoneResponse)
async def get_phone(
    phone_uuid: UUID,
    user=Depends(get_user_or_404),
    service: PhoneService = Depends(get_phone_service),
) -> PhoneResponse:
    phone = await service.get_by_uuid(phone_uuid)
    if not phone or phone.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Phone not found")
    return PhoneResponse.model_validate(phone)


@router.post("", response_model=PhoneResponse, status_code=status.HTTP_201_CREATED)
async def create_phone(
    data: PhoneCreate,
    user=Depends(get_user_or_404),
    service: PhoneService = Depends(get_phone_service),
    session: AsyncSession = Depends(get_session),
) -> PhoneResponse:
    existing = await service.get_by_number(data.phone_number)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Phone number already exists",
        )
    phone = await service.create_for_user(user.id, data)
    if data.is_primary:
        await service.set_primary_phone(user.id, phone.id)
    await session.commit()
    return PhoneResponse.model_validate(phone)


@router.patch("/{phone_uuid}", response_model=PhoneResponse)
async def update_phone(
    phone_uuid: UUID,
    data: PhoneUpdate,
    user=Depends(get_user_or_404),
    service: PhoneService = Depends(get_phone_service),
    session: AsyncSession = Depends(get_session),
) -> PhoneResponse:
    phone = await service.get_by_uuid(phone_uuid)
    if not phone or phone.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Phone not found")

    if data.phone_number:
        existing = await service.get_by_number(data.phone_number)
        if existing and existing.uuid != phone.uuid:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Phone number already exists",
            )

    if data.is_primary:
        await service.set_primary_phone(user.id, phone.id)

    updated = await service.update(phone.id, data)
    await session.commit()
    return PhoneResponse.model_validate(updated)


@router.delete("/{phone_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_phone(
    phone_uuid: UUID,
    user=Depends(get_user_or_404),
    service: PhoneService = Depends(get_phone_service),
    session: AsyncSession = Depends(get_session),
) -> None:
    phone = await service.get_by_uuid(phone_uuid)
    if not phone or phone.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Phone not found")
    await service.soft_delete(phone.id)
    await session.commit()


@router.post("/{phone_uuid}/set-primary", response_model=PhoneResponse)
async def set_primary_phone(
    phone_uuid: UUID,
    user=Depends(get_user_or_404),
    service: PhoneService = Depends(get_phone_service),
    session: AsyncSession = Depends(get_session),
) -> PhoneResponse:
    phone = await service.get_by_uuid(phone_uuid)
    if not phone or phone.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Phone not found")
    result = await service.set_primary_phone(user.id, phone.id)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Phone not found")
    await session.commit()
    return PhoneResponse.model_validate(result)
