"""User schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import Field

from src.schemas.base import BaseResponse, BaseSchema


class UserCreate(BaseSchema):
    username: str = Field(..., min_length=3, max_length=255)
    password: str | None = Field(None, min_length=8, max_length=255)
    is_admin: bool = False


class UserUpdate(BaseSchema):
    username: str | None = Field(None, min_length=3, max_length=255)
    is_admin: bool | None = None
    is_active: bool | None = None


class UserResponse(BaseResponse):
    username: str
    is_admin: bool
    last_login: datetime | None


class UserListResponse(BaseSchema):
    uuid: UUID
    username: str
    is_admin: bool
    is_active: bool
