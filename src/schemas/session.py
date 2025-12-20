"""Session schemas."""

from datetime import datetime

from src.schemas.base import BaseSchema


class SessionResponse(BaseSchema):
    """Active session information response."""

    uuid: str
    device_type: str | None
    browser: str | None
    os: str | None
    device_brand: str | None
    device_model: str | None
    country: str | None
    city: str | None
    ip_address: str
    created_at: datetime
    last_activity_at: datetime
    is_current: bool = False


class SessionListResponse(BaseSchema):
    """List of active sessions."""

    sessions: list[SessionResponse]
    total: int
