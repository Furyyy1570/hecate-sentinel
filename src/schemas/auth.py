"""Authentication schemas."""

from pydantic import EmailStr, Field

from src.schemas.base import BaseSchema


# === Request Schemas ===


class LoginRequest(BaseSchema):
    """Username or email/password login request."""

    login: str = Field(..., min_length=3, max_length=255, description="Username or email")
    password: str = Field(..., min_length=8, max_length=255)


class RegisterRequest(BaseSchema):
    """User registration request."""

    username: str = Field(..., min_length=3, max_length=255)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=255)


class MagicLinkRequest(BaseSchema):
    """Request magic link login."""

    email: EmailStr


class MagicLinkVerifyRequest(BaseSchema):
    """Verify magic link token."""

    token: str = Field(..., min_length=32)


class PasswordResetRequest(BaseSchema):
    """Request password reset."""

    email: EmailStr


class PasswordResetConfirmRequest(BaseSchema):
    """Confirm password reset with new password."""

    token: str = Field(..., min_length=32)
    new_password: str = Field(..., min_length=8, max_length=255)


class EmailVerifyRequest(BaseSchema):
    """Verify email address."""

    token: str = Field(..., min_length=32)


class RefreshTokenRequest(BaseSchema):
    """Refresh access token."""

    refresh_token: str


class ChangePasswordRequest(BaseSchema):
    """Change password (authenticated user)."""

    current_password: str = Field(..., min_length=8, max_length=255)
    new_password: str = Field(..., min_length=8, max_length=255)


# === Response Schemas ===


class TokenResponse(BaseSchema):
    """JWT token response."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class LoginResponse(BaseSchema):
    """Login response - either tokens or TOTP required."""

    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str | None = None
    expires_in: int | None = None
    requires_totp: bool = False
    totp_token: str | None = None


class MessageResponse(BaseSchema):
    """Generic message response."""

    message: str


class AuthUserResponse(BaseSchema):
    """Authenticated user info response."""

    uuid: str
    username: str
    email: str | None
    is_admin: bool
    email_verified: bool
