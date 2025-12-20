"""TOTP utilities for two-factor authentication."""

import base64
import io
import secrets

import pyotp
import qrcode

from src.core.settings import get_settings

settings = get_settings()

# Recovery code configuration
RECOVERY_CODE_COUNT = 8
RECOVERY_CODE_LENGTH = 16


def generate_totp_secret() -> str:
    """Generate a new TOTP secret."""
    return pyotp.random_base32()


def get_totp(secret: str) -> pyotp.TOTP:
    """Get a TOTP instance for the given secret."""
    return pyotp.TOTP(secret)


def verify_totp_code(secret: str, code: str) -> bool:
    """Verify a TOTP code against the secret."""
    totp = get_totp(secret)
    # Allow 1 window before and after for clock drift
    return totp.verify(code, valid_window=1)


def get_provisioning_uri(secret: str, username: str) -> str:
    """Generate the otpauth:// URI for authenticator apps."""
    totp = get_totp(secret)
    return totp.provisioning_uri(name=username, issuer_name=settings.app_name)


def generate_qr_code(provisioning_uri: str) -> str:
    """Generate a base64-encoded QR code PNG for the provisioning URI."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)

    return base64.b64encode(buffer.getvalue()).decode("utf-8")


def generate_recovery_code() -> str:
    """Generate a single recovery code."""
    # Generate random bytes and encode as alphanumeric
    code = secrets.token_hex(RECOVERY_CODE_LENGTH // 2).upper()
    # Format as XXXX-XXXX-XXXX-XXXX for readability
    return "-".join(code[i : i + 4] for i in range(0, len(code), 4))


def generate_recovery_codes() -> list[str]:
    """Generate a set of recovery codes."""
    return [generate_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]


def normalize_recovery_code(code: str) -> str:
    """Normalize recovery code for comparison (remove dashes, uppercase)."""
    return code.replace("-", "").upper()
