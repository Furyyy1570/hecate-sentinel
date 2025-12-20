"""Email API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_session
from src.schemas.email import EmailCreate, EmailResponse, EmailUpdate
from src.services.email import EmailService
from src.services.user import UserService

router = APIRouter(prefix="/users/{user_uuid}/emails", tags=["emails"])


def get_email_service(session: AsyncSession = Depends(get_session)) -> EmailService:
    return EmailService(session)


def get_user_service(session: AsyncSession = Depends(get_session)) -> UserService:
    return UserService(session)


async def get_user_or_404(user_uuid: UUID, user_service: UserService = Depends(get_user_service)):
    user = await user_service.get_by_uuid(user_uuid)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("", response_model=list[EmailResponse])
async def list_user_emails(
    user=Depends(get_user_or_404),
    service: EmailService = Depends(get_email_service),
) -> list[EmailResponse]:
    emails = await service.get_by_user(user.id)
    return [EmailResponse.model_validate(e) for e in emails]


@router.get("/{email_uuid}", response_model=EmailResponse)
async def get_email(
    email_uuid: UUID,
    user=Depends(get_user_or_404),
    service: EmailService = Depends(get_email_service),
) -> EmailResponse:
    email = await service.get_by_uuid(email_uuid)
    if not email or email.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")
    return EmailResponse.model_validate(email)


@router.post("", response_model=EmailResponse, status_code=status.HTTP_201_CREATED)
async def create_email(
    data: EmailCreate,
    user=Depends(get_user_or_404),
    service: EmailService = Depends(get_email_service),
    session: AsyncSession = Depends(get_session),
) -> EmailResponse:
    existing = await service.get_by_address(data.email_address)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email address already exists",
        )
    email = await service.create_for_user(user.id, data)
    if data.is_primary:
        await service.set_primary_email(user.id, email.id)
    await session.commit()
    return EmailResponse.model_validate(email)


@router.patch("/{email_uuid}", response_model=EmailResponse)
async def update_email(
    email_uuid: UUID,
    data: EmailUpdate,
    user=Depends(get_user_or_404),
    service: EmailService = Depends(get_email_service),
    session: AsyncSession = Depends(get_session),
) -> EmailResponse:
    email = await service.get_by_uuid(email_uuid)
    if not email or email.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")

    if data.email_address:
        existing = await service.get_by_address(data.email_address)
        if existing and existing.uuid != email.uuid:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email address already exists",
            )

    if data.is_primary:
        await service.set_primary_email(user.id, email.id)

    updated = await service.update(email.id, data)
    await session.commit()
    return EmailResponse.model_validate(updated)


@router.delete("/{email_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_email(
    email_uuid: UUID,
    user=Depends(get_user_or_404),
    service: EmailService = Depends(get_email_service),
    session: AsyncSession = Depends(get_session),
) -> None:
    email = await service.get_by_uuid(email_uuid)
    if not email or email.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")
    await service.soft_delete(email.id)
    await session.commit()


@router.post("/{email_uuid}/set-primary", response_model=EmailResponse)
async def set_primary_email(
    email_uuid: UUID,
    user=Depends(get_user_or_404),
    service: EmailService = Depends(get_email_service),
    session: AsyncSession = Depends(get_session),
) -> EmailResponse:
    email = await service.get_by_uuid(email_uuid)
    if not email or email.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")
    result = await service.set_primary_email(user.id, email.id)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")
    await session.commit()
    return EmailResponse.model_validate(result)
