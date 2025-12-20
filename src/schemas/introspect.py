"""Schemas for token introspection."""

from uuid import UUID

from pydantic import BaseModel, Field


class IntrospectRequest(BaseModel):
    """Request body for token introspection."""

    token: str = Field(..., description="The JWT token to validate")


class IntrospectResponse(BaseModel):
    """Response for token introspection."""

    valid: bool = Field(..., description="Whether the token is valid")
    user_id: UUID | None = Field(None, description="User UUID if valid")
    username: str | None = Field(None, description="Username if valid")
    is_admin: bool | None = Field(None, description="Admin status if valid")
    roles: list[str] | None = Field(None, description="User's roles (group names) if valid")
    permissions: list[str] | None = Field(None, description="User's permissions if valid")


class ServiceAPIKeyCreate(BaseModel):
    """Request to create a new service API key."""

    name: str = Field(..., min_length=1, max_length=255, description="Service name")
    description: str | None = Field(None, description="Optional description")


class ServiceAPIKeyResponse(BaseModel):
    """Response after creating a service API key."""

    name: str
    key_prefix: str
    api_key: str = Field(..., description="The full API key (only shown once)")


class ServiceAPIKeyInfo(BaseModel):
    """Info about a service API key (without the key itself)."""

    uuid: UUID
    name: str
    description: str | None
    key_prefix: str
    is_active: bool
