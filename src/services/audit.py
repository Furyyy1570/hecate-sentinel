"""Security audit logging service."""

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.request_context import RequestContext
from src.models.audit_log import AuditEventType, AuditLog
from src.models.user import User


class AuditService:
    """Service for security audit logging."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def log_event(
        self,
        event_type: AuditEventType,
        user: User | None = None,
        context: RequestContext | None = None,
        success: bool = True,
        failure_reason: str | None = None,
        event_data: dict[str, Any] | None = None,
        session_id: int | None = None,
        country: str | None = None,
        city: str | None = None,
    ) -> AuditLog:
        """Log a security event."""
        now = datetime.now(timezone.utc)

        log = AuditLog(
            user_id=user.id if user else None,
            event_type=event_type,
            event_timestamp=now,
            ip_address=context.ip_address if context else None,
            user_agent=context.user_agent if context else None,
            request_id=context.request_id if context else None,
            country=country,
            city=city,
            event_data=event_data,
            success=success,
            failure_reason=failure_reason,
            session_id=session_id,
        )
        self.session.add(log)
        await self.session.flush()

        return log

    async def get_user_logs(
        self,
        user: User,
        event_types: list[AuditEventType] | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        success_only: bool | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[AuditLog], int]:
        """Get audit logs for a user with filtering and pagination."""
        # Build query
        conditions = [AuditLog.user_id == user.id]

        if event_types:
            conditions.append(AuditLog.event_type.in_(event_types))

        if start_date:
            conditions.append(AuditLog.event_timestamp >= start_date)

        if end_date:
            conditions.append(AuditLog.event_timestamp <= end_date)

        if success_only is not None:
            conditions.append(AuditLog.success == success_only)

        # Get total count
        count_result = await self.session.execute(
            select(func.count(AuditLog.id)).where(and_(*conditions))
        )
        total = count_result.scalar_one()

        # Get paginated results
        offset = (page - 1) * page_size
        result = await self.session.execute(
            select(AuditLog)
            .where(and_(*conditions))
            .order_by(AuditLog.event_timestamp.desc())
            .offset(offset)
            .limit(page_size)
        )
        logs = list(result.scalars().all())

        return logs, total

    async def get_recent_failed_logins(
        self,
        user: User | None = None,
        ip_address: str | None = None,
        minutes: int = 30,
    ) -> int:
        """Count recent failed login attempts (for rate limiting)."""
        now = datetime.now(timezone.utc)
        since = now - timedelta(minutes=minutes)

        conditions = [
            AuditLog.event_type == AuditEventType.LOGIN_FAILED,
            AuditLog.event_timestamp >= since,
        ]

        if user:
            conditions.append(AuditLog.user_id == user.id)

        if ip_address:
            conditions.append(AuditLog.ip_address == ip_address)

        result = await self.session.execute(
            select(func.count(AuditLog.id)).where(and_(*conditions))
        )
        return result.scalar_one()
