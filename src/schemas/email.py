"""Email schemas."""

from pydantic import EmailStr

from src.schemas.base import BaseResponse, BaseSchema


class EmailCreate(BaseSchema):
    email_address: EmailStr
    is_primary: bool = False
    is_verified: bool = False


class EmailUpdate(BaseSchema):
    email_address: EmailStr | None = None
    is_primary: bool | None = None
    is_verified: bool | None = None
    is_active: bool | None = None


class EmailResponse(BaseResponse):
    email_address: str
    is_primary: bool
    is_verified: bool
