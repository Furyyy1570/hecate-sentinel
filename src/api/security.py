"""Security audit API routes."""

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_current_user
from src.core.database import get_session
from src.models.audit_log import AuditEventType
from src.models.user import User
from src.schemas.audit import AuditLogListResponse, AuditLogResponse
from src.schemas.device import (
    KnownDeviceListResponse,
    KnownDeviceResponse,
    KnownLocationListResponse,
    KnownLocationResponse,
)
from src.services.audit import AuditService
from src.services.session import SessionService

router = APIRouter(prefix="/security", tags=["security"])


def get_audit_service(
    db_session: AsyncSession = Depends(get_session),
) -> AuditService:
    return AuditService(db_session)


def get_session_service(
    db_session: AsyncSession = Depends(get_session),
) -> SessionService:
    return SessionService(db_session)


@router.get("/audit-log", response_model=AuditLogListResponse)
async def get_audit_log(
    current_user: User = Depends(get_current_user),
    audit_service: AuditService = Depends(get_audit_service),
    event_types: list[AuditEventType] | None = Query(None),
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    success_only: bool | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
) -> AuditLogListResponse:
    """Get security audit log for the current user."""
    logs, total = await audit_service.get_user_logs(
        user=current_user,
        event_types=event_types,
        start_date=start_date,
        end_date=end_date,
        success_only=success_only,
        page=page,
        page_size=page_size,
    )

    return AuditLogListResponse(
        logs=[
            AuditLogResponse(
                uuid=str(log.uuid),
                event_type=log.event_type,
                event_timestamp=log.event_timestamp,
                ip_address=log.ip_address,
                country=log.country,
                city=log.city,
                success=log.success,
                failure_reason=log.failure_reason,
                event_data=log.event_data,
            )
            for log in logs
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/devices", response_model=KnownDeviceListResponse)
async def get_known_devices(
    current_user: User = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
) -> KnownDeviceListResponse:
    """Get all known devices for the current user."""
    devices = await session_service.get_known_devices(current_user)

    return KnownDeviceListResponse(
        devices=[
            KnownDeviceResponse(
                uuid=str(d.uuid),
                device_type=d.device_type,
                browser=d.browser,
                os=d.os,
                device_brand=d.device_brand,
                device_model=d.device_model,
                friendly_name=d.friendly_name,
                first_seen_at=d.first_seen_at,
                last_seen_at=d.last_seen_at,
                is_trusted=d.is_trusted,
            )
            for d in devices
        ],
        total=len(devices),
    )


@router.get("/locations", response_model=KnownLocationListResponse)
async def get_known_locations(
    current_user: User = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
) -> KnownLocationListResponse:
    """Get all known login locations for the current user."""
    locations = await session_service.get_known_locations(current_user)

    return KnownLocationListResponse(
        locations=[
            KnownLocationResponse(
                uuid=str(loc.uuid),
                country=loc.country,
                city=loc.city,
                region=loc.region,
                first_seen_at=loc.first_seen_at,
                last_seen_at=loc.last_seen_at,
                is_trusted=loc.is_trusted,
            )
            for loc in locations
        ],
        total=len(locations),
    )
