"""Permission schemas."""

from pydantic import Field

from src.schemas.base import BaseResponse, BaseSchema


class PermissionCreate(BaseSchema):
    name: str = Field(..., min_length=1, max_length=255)


class PermissionUpdate(BaseSchema):
    name: str | None = Field(None, min_length=1, max_length=255)
    is_active: bool | None = None


class PermissionResponse(BaseResponse):
    name: str
