"""OAuth account schemas."""

from datetime import datetime

from pydantic import Field

from src.schemas.base import BaseResponse, BaseSchema


class OAuthAccountCreate(BaseSchema):
    provider: str = Field(..., min_length=1, max_length=50)
    provider_user_id: str = Field(..., min_length=1, max_length=255)
    access_token: str | None = None
    refresh_token: str | None = None
    expires_at: datetime | None = None


class OAuthAccountUpdate(BaseSchema):
    access_token: str | None = None
    refresh_token: str | None = None
    expires_at: datetime | None = None
    is_active: bool | None = None


class OAuthAccountResponse(BaseResponse):
    provider: str
    provider_user_id: str
    expires_at: datetime | None
