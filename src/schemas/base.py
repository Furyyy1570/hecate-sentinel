"""Base schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class BaseResponse(BaseSchema):
    uuid: UUID
    pub_date: datetime
    mod_date: datetime
    is_active: bool
    is_deleted: bool
