"""Group schemas."""

from uuid import UUID

from pydantic import Field

from src.schemas.base import BaseResponse, BaseSchema


class GroupCreate(BaseSchema):
    name: str = Field(..., min_length=1, max_length=255)


class GroupUpdate(BaseSchema):
    name: str | None = Field(None, min_length=1, max_length=255)
    is_active: bool | None = None


class GroupResponse(BaseResponse):
    name: str


class GroupWithUsersResponse(GroupResponse):
    user_count: int = 0


class GroupAddUser(BaseSchema):
    user_uuid: UUID


class GroupAddPermission(BaseSchema):
    permission_uuid: UUID
