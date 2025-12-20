"""Tests for TOTP utilities."""

import base64

import pyotp
import pytest

from src.core.totp import (
    RECOVERY_CODE_COUNT,
    RECOVERY_CODE_LENGTH,
    generate_qr_code,
    generate_recovery_code,
    generate_recovery_codes,
    generate_totp_secret,
    get_provisioning_uri,
    get_totp,
    normalize_recovery_code,
    verify_totp_code,
)


class TestTOTPSecret:
    """Tests for TOTP secret generation."""

    def test_generate_totp_secret(self):
        """Test generating a TOTP secret."""
        secret = generate_totp_secret()

        assert isinstance(secret, str)
        assert len(secret) == 32  # Base32 encoded

    def test_generate_totp_secret_unique(self):
        """Test that secrets are unique."""
        secrets = [generate_totp_secret() for _ in range(100)]

        assert len(set(secrets)) == 100

    def test_generate_totp_secret_valid_base32(self):
        """Test that secret is valid base32."""
        secret = generate_totp_secret()

        # Should not raise
        base64.b32decode(secret)


class TestTOTPVerification:
    """Tests for TOTP code verification."""

    def test_get_totp(self):
        """Test getting a TOTP instance."""
        secret = generate_totp_secret()
        totp = get_totp(secret)

        assert isinstance(totp, pyotp.TOTP)

    def test_verify_totp_code_valid(self):
        """Test verifying a valid TOTP code."""
        secret = generate_totp_secret()
        totp = get_totp(secret)
        code = totp.now()

        assert verify_totp_code(secret, code) is True

    def test_verify_totp_code_invalid(self):
        """Test verifying an invalid TOTP code."""
        secret = generate_totp_secret()

        assert verify_totp_code(secret, "000000") is False
        assert verify_totp_code(secret, "123456") is False

    def test_verify_totp_code_wrong_format(self):
        """Test verifying code with wrong format."""
        secret = generate_totp_secret()

        assert verify_totp_code(secret, "12345") is False  # Too short
        assert verify_totp_code(secret, "1234567") is False  # Too long
        assert verify_totp_code(secret, "abcdef") is False  # Non-numeric


class TestProvisioningURI:
    """Tests for provisioning URI generation."""

    def test_get_provisioning_uri(self):
        """Test generating provisioning URI."""
        secret = generate_totp_secret()
        uri = get_provisioning_uri(secret, "testuser")

        assert uri.startswith("otpauth://totp/")
        assert "testuser" in uri
        assert secret in uri

    def test_provisioning_uri_contains_issuer(self):
        """Test that URI contains issuer."""
        secret = generate_totp_secret()
        uri = get_provisioning_uri(secret, "testuser")

        assert "issuer=" in uri


class TestQRCode:
    """Tests for QR code generation."""

    def test_generate_qr_code(self):
        """Test generating a QR code."""
        secret = generate_totp_secret()
        uri = get_provisioning_uri(secret, "testuser")
        qr_base64 = generate_qr_code(uri)

        assert isinstance(qr_base64, str)
        # Should be valid base64
        decoded = base64.b64decode(qr_base64)
        # Should be a PNG (starts with PNG magic bytes)
        assert decoded[:8] == b"\x89PNG\r\n\x1a\n"


class TestRecoveryCodes:
    """Tests for recovery code generation."""

    def test_generate_recovery_code_format(self):
        """Test recovery code format."""
        code = generate_recovery_code()

        # Should be XXXX-XXXX-XXXX-XXXX format
        parts = code.split("-")
        assert len(parts) == 4
        assert all(len(part) == 4 for part in parts)
        assert all(part.isalnum() for part in parts)

    def test_generate_recovery_code_uppercase(self):
        """Test that recovery codes are uppercase."""
        code = generate_recovery_code()

        assert code == code.upper()

    def test_generate_recovery_code_unique(self):
        """Test that recovery codes are unique."""
        codes = [generate_recovery_code() for _ in range(100)]

        assert len(set(codes)) == 100

    def test_generate_recovery_codes_count(self):
        """Test generating the correct number of recovery codes."""
        codes = generate_recovery_codes()

        assert len(codes) == RECOVERY_CODE_COUNT

    def test_generate_recovery_codes_all_unique(self):
        """Test that all recovery codes in a set are unique."""
        codes = generate_recovery_codes()

        assert len(set(codes)) == len(codes)


class TestNormalizeRecoveryCode:
    """Tests for recovery code normalization."""

    def test_normalize_removes_dashes(self):
        """Test that normalization removes dashes."""
        code = "ABCD-1234-EFGH-5678"
        normalized = normalize_recovery_code(code)

        assert "-" not in normalized
        assert normalized == "ABCD1234EFGH5678"

    def test_normalize_uppercase(self):
        """Test that normalization uppercases."""
        code = "abcd-1234-efgh-5678"
        normalized = normalize_recovery_code(code)

        assert normalized == "ABCD1234EFGH5678"

    def test_normalize_already_normalized(self):
        """Test normalizing already normalized code."""
        code = "ABCD1234EFGH5678"
        normalized = normalize_recovery_code(code)

        assert normalized == code

    def test_normalize_mixed_case_with_dashes(self):
        """Test normalizing mixed case with dashes."""
        code = "AbCd-1234-EfGh-5678"
        normalized = normalize_recovery_code(code)

        assert normalized == "ABCD1234EFGH5678"
