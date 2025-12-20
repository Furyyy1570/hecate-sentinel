"""Phone schemas."""

from pydantic import Field

from src.schemas.base import BaseResponse, BaseSchema


class PhoneCreate(BaseSchema):
    phone_number: str = Field(..., min_length=5, max_length=50)
    is_primary: bool = False
    is_verified: bool = False


class PhoneUpdate(BaseSchema):
    phone_number: str | None = Field(None, min_length=5, max_length=50)
    is_primary: bool | None = None
    is_verified: bool | None = None
    is_active: bool | None = None


class PhoneResponse(BaseResponse):
    phone_number: str
    is_primary: bool
    is_verified: bool
