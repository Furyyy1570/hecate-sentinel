"""Device and location schemas."""

from datetime import datetime

from pydantic import Field

from src.schemas.base import BaseSchema


class KnownDeviceResponse(BaseSchema):
    """Known device information response."""

    uuid: str
    device_type: str | None
    browser: str | None
    os: str | None
    device_brand: str | None
    device_model: str | None
    friendly_name: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    is_trusted: bool


class KnownDeviceListResponse(BaseSchema):
    """List of known devices."""

    devices: list[KnownDeviceResponse]
    total: int


class KnownDeviceUpdateRequest(BaseSchema):
    """Update known device."""

    friendly_name: str | None = Field(None, max_length=100)
    is_trusted: bool | None = None


class KnownLocationResponse(BaseSchema):
    """Known location information response."""

    uuid: str
    country: str | None
    city: str | None
    region: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    is_trusted: bool


class KnownLocationListResponse(BaseSchema):
    """List of known locations."""

    locations: list[KnownLocationResponse]
    total: int
