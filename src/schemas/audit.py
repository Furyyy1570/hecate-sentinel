"""Audit log schemas."""

from datetime import datetime
from typing import Any

from pydantic import Field

from src.models.audit_log import AuditEventType
from src.schemas.base import BaseSchema


class AuditLogResponse(BaseSchema):
    """Audit log entry response."""

    uuid: str
    event_type: AuditEventType
    event_timestamp: datetime
    ip_address: str | None
    country: str | None
    city: str | None
    success: bool
    failure_reason: str | None
    event_data: dict[str, Any] | None


class AuditLogListResponse(BaseSchema):
    """List of audit log entries."""

    logs: list[AuditLogResponse]
    total: int
    page: int
    page_size: int


class AuditLogFilterParams(BaseSchema):
    """Filter parameters for audit log queries."""

    event_types: list[AuditEventType] | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    success_only: bool | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=100)
