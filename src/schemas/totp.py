"""TOTP schemas."""

from pydantic import Field

from src.schemas.base import BaseSchema


# === Request Schemas ===


class TOTPEnableRequest(BaseSchema):
    """Confirm TOTP setup with verification code."""

    code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class TOTPVerifyRequest(BaseSchema):
    """Verify TOTP during login."""

    totp_token: str = Field(..., description="Temporary token from login")
    code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class TOTPDisableRequest(BaseSchema):
    """Disable TOTP (requires password and current code)."""

    password: str = Field(..., min_length=8, max_length=255)
    code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class RecoveryCodeVerifyRequest(BaseSchema):
    """Verify using recovery code during login."""

    totp_token: str = Field(..., description="Temporary token from login")
    code: str = Field(..., min_length=16, max_length=24)


# === Response Schemas ===


class TOTPSetupResponse(BaseSchema):
    """TOTP setup information."""

    secret: str
    provisioning_uri: str
    qr_code: str  # Base64 encoded PNG


class TOTPStatusResponse(BaseSchema):
    """TOTP status for user."""

    enabled: bool
    recovery_codes_remaining: int


class RecoveryCodesResponse(BaseSchema):
    """New recovery codes (only shown once)."""

    codes: list[str]
