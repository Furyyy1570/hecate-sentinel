"""Session management API routes."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_current_user
from src.core.database import get_session
from src.core.request_context import get_request_context
from src.models.audit_log import AuditEventType
from src.models.user import User
from src.schemas.auth import MessageResponse
from src.schemas.session import SessionListResponse, SessionResponse
from src.services.audit import AuditService
from src.services.session import SessionService

router = APIRouter(prefix="/sessions", tags=["sessions"])


def get_session_service(
    db_session: AsyncSession = Depends(get_session),
) -> SessionService:
    return SessionService(db_session)


def get_audit_service(
    db_session: AsyncSession = Depends(get_session),
) -> AuditService:
    return AuditService(db_session)


@router.get("", response_model=SessionListResponse)
async def list_sessions(
    request: Request,
    current_user: User = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
) -> SessionListResponse:
    """Get all active sessions for the current user."""
    # Get current session's token hash for marking current session
    refresh_token = request.headers.get("x-refresh-token")
    current_hash = (
        session_service._hash_token(refresh_token) if refresh_token else None
    )

    sessions_with_current = await session_service.get_active_sessions(
        current_user, current_hash
    )

    return SessionListResponse(
        sessions=[
            SessionResponse(
                uuid=str(s.uuid),
                device_type=s.device_type,
                browser=s.browser,
                os=s.os,
                device_brand=s.device_brand,
                device_model=s.device_model,
                country=s.country,
                city=s.city,
                ip_address=s.ip_address,
                created_at=s.created_at,
                last_activity_at=s.last_activity_at,
                is_current=is_current,
            )
            for s, is_current in sessions_with_current
        ],
        total=len(sessions_with_current),
    )


@router.delete("/{session_uuid}", response_model=MessageResponse)
async def revoke_session(
    session_uuid: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
    audit_service: AuditService = Depends(get_audit_service),
    db_session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Revoke a specific session."""
    context = get_request_context(request)

    success = await session_service.revoke_session(current_user, session_uuid)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    # Log the event
    await audit_service.log_event(
        event_type=AuditEventType.SESSION_REVOKED,
        user=current_user,
        context=context,
        event_data={"revoked_session_uuid": session_uuid},
    )

    await db_session.commit()
    return MessageResponse(message="Session revoked successfully")


@router.delete("", response_model=MessageResponse)
async def revoke_all_sessions(
    request: Request,
    keep_current: bool = True,
    current_user: User = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
    audit_service: AuditService = Depends(get_audit_service),
    db_session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Revoke all sessions for the current user."""
    context = get_request_context(request)
    refresh_token = request.headers.get("x-refresh-token")
    current_hash = (
        session_service._hash_token(refresh_token)
        if refresh_token and keep_current
        else None
    )

    count = await session_service.revoke_all_sessions(current_user, current_hash)

    # Log the event
    await audit_service.log_event(
        event_type=AuditEventType.LOGOUT_ALL,
        user=current_user,
        context=context,
        event_data={"sessions_revoked": count, "kept_current": keep_current},
    )

    await db_session.commit()
    return MessageResponse(message=f"{count} sessions revoked")
