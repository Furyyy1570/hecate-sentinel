"""Tests for AuthService."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from src.core.security import hash_password
from src.models.email import Email
from src.models.email_verification import EmailVerificationToken
from src.models.password_reset import PasswordResetToken
from src.models.recovery_code import RecoveryCode
from src.models.user import User
from src.services.auth import AuthService


class TestAuthServiceUserLookup:
    """Tests for user lookup methods."""

    @pytest.mark.asyncio
    async def test_get_user_by_username(self, db_session, test_user):
        """Test getting user by username."""
        auth_service = AuthService(db_session)

        user = await auth_service.get_user_by_username(test_user.username)

        assert user is not None
        assert user.id == test_user.id

    @pytest.mark.asyncio
    async def test_get_user_by_username_not_found(self, db_session):
        """Test getting non-existent user by username."""
        auth_service = AuthService(db_session)

        user = await auth_service.get_user_by_username("nonexistent")

        assert user is None

    @pytest.mark.asyncio
    async def test_get_user_by_email(self, db_session, verified_user):
        """Test getting user by email."""
        auth_service = AuthService(db_session)

        user = await auth_service.get_user_by_email("test@example.com")

        assert user is not None
        assert user.id == verified_user.id

    @pytest.mark.asyncio
    async def test_get_user_by_uuid(self, db_session, test_user):
        """Test getting user by UUID."""
        auth_service = AuthService(db_session)

        user = await auth_service.get_user_by_uuid(str(test_user.uuid))

        assert user is not None
        assert user.id == test_user.id


class TestAuthServiceAuthentication:
    """Tests for authentication methods."""

    @pytest.mark.asyncio
    async def test_authenticate_user_by_username(self, db_session, test_user):
        """Test authenticating user by username."""
        auth_service = AuthService(db_session)

        user = await auth_service.authenticate_user(
            test_user.username,
            "testpassword123",
        )

        assert user is not None
        assert user.id == test_user.id

    @pytest.mark.asyncio
    async def test_authenticate_user_by_email(self, db_session, verified_user):
        """Test authenticating user by email."""
        auth_service = AuthService(db_session)

        user = await auth_service.authenticate_user(
            "test@example.com",
            "testpassword123",
        )

        assert user is not None
        assert user.id == verified_user.id

    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password(self, db_session, test_user):
        """Test authentication with wrong password."""
        auth_service = AuthService(db_session)

        user = await auth_service.authenticate_user(
            test_user.username,
            "wrongpassword",
        )

        assert user is None

    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self, db_session):
        """Test authentication with non-existent user."""
        auth_service = AuthService(db_session)

        user = await auth_service.authenticate_user(
            "nonexistent",
            "password",
        )

        assert user is None


class TestAuthServiceTokens:
    """Tests for token creation methods."""

    @pytest.mark.asyncio
    async def test_create_tokens(self, db_session, test_user):
        """Test creating tokens without context."""
        auth_service = AuthService(db_session)

        tokens, is_new_device, is_new_location, session, geo, device_info = (
            await auth_service.create_tokens(test_user)
        )

        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert tokens["token_type"] == "bearer"
        assert is_new_device is False
        assert is_new_location is False
        assert session is None

    @pytest.mark.asyncio
    async def test_create_tokens_with_context(
        self, db_session, test_user, request_context
    ):
        """Test creating tokens with context."""
        from src.core.geoip import GeoLocation

        mock_geo = GeoLocation(country="US", city="NYC")

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            auth_service = AuthService(db_session)

            tokens, is_new_device, is_new_location, session, geo, device_info = (
                await auth_service.create_tokens(test_user, request_context)
            )

            assert "access_token" in tokens
            assert session is not None
            assert is_new_device is True

    @pytest.mark.asyncio
    async def test_validate_refresh_token(self, db_session, test_user):
        """Test validating refresh token."""
        auth_service = AuthService(db_session)

        tokens, _, _, _, _, _ = await auth_service.create_tokens(test_user)

        user = await auth_service.validate_refresh_token(tokens["refresh_token"])

        assert user is not None
        assert user.id == test_user.id

    @pytest.mark.asyncio
    async def test_validate_refresh_token_invalid(self, db_session):
        """Test validating invalid refresh token."""
        auth_service = AuthService(db_session)

        user = await auth_service.validate_refresh_token("invalid_token")

        assert user is None


class TestAuthServiceRegistration:
    """Tests for registration methods."""

    @pytest.mark.asyncio
    async def test_register_user(self, db_session):
        """Test user registration."""
        auth_service = AuthService(db_session)

        user, token = await auth_service.register_user(
            username="newuser",
            email_address="new@example.com",
            password="securepassword123",
        )
        await db_session.flush()

        assert user.id is not None
        assert user.username == "newuser"
        assert token is not None
        assert len(token) > 20


class TestAuthServiceEmailVerification:
    """Tests for email verification methods."""

    @pytest.mark.asyncio
    async def test_verify_email(self, db_session):
        """Test email verification."""
        auth_service = AuthService(db_session)

        # Register user
        user, token = await auth_service.register_user(
            username="verifyuser",
            email_address="verify@example.com",
            password="password123",
        )
        await db_session.flush()

        # Verify email
        result = await auth_service.verify_email(token)

        assert result is True

    @pytest.mark.asyncio
    async def test_verify_email_invalid_token(self, db_session):
        """Test email verification with invalid token."""
        auth_service = AuthService(db_session)

        result = await auth_service.verify_email("invalid_token")

        assert result is False

    @pytest.mark.asyncio
    async def test_has_verified_email_false(self, db_session, test_user):
        """Test checking for verified email when none exists."""
        auth_service = AuthService(db_session)

        # Reload user with emails
        user = await auth_service.get_user_by_username(test_user.username)
        result = await auth_service.has_verified_email(user)

        assert result is False

    @pytest.mark.asyncio
    async def test_has_verified_email_true(self, db_session, verified_user):
        """Test checking for verified email when one exists."""
        auth_service = AuthService(db_session)

        # Reload user with emails
        user = await auth_service.get_user_by_username(verified_user.username)
        result = await auth_service.has_verified_email(user)

        assert result is True


class TestAuthServicePasswordReset:
    """Tests for password reset methods."""

    @pytest.mark.asyncio
    async def test_create_password_reset_token(self, db_session, verified_user):
        """Test creating password reset token."""
        auth_service = AuthService(db_session)

        result = await auth_service.create_password_reset_token("test@example.com")

        assert result is not None
        user, token = result
        assert user.id == verified_user.id
        assert len(token) > 20

    @pytest.mark.asyncio
    async def test_create_password_reset_token_not_found(self, db_session):
        """Test creating reset token for non-existent email."""
        auth_service = AuthService(db_session)

        result = await auth_service.create_password_reset_token(
            "nonexistent@example.com"
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_reset_password(self, db_session, verified_user):
        """Test resetting password."""
        auth_service = AuthService(db_session)

        # Create reset token
        _, token = await auth_service.create_password_reset_token("test@example.com")
        await db_session.flush()

        # Reset password
        result = await auth_service.reset_password(token, "newpassword123")

        assert result is True

        # Verify can login with new password
        user = await auth_service.authenticate_user(
            verified_user.username,
            "newpassword123",
        )
        assert user is not None


class TestAuthServicePasswordChange:
    """Tests for password change methods."""

    @pytest.mark.asyncio
    async def test_change_password(self, db_session, test_user):
        """Test changing password."""
        auth_service = AuthService(db_session)

        result = await auth_service.change_password(
            test_user,
            "testpassword123",
            "newpassword456",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_change_password_wrong_current(self, db_session, test_user):
        """Test changing password with wrong current password."""
        auth_service = AuthService(db_session)

        result = await auth_service.change_password(
            test_user,
            "wrongpassword",
            "newpassword456",
        )

        assert result is False


class TestAuthServiceTOTP:
    """Tests for TOTP methods."""

    @pytest.mark.asyncio
    async def test_setup_totp(self, db_session, test_user):
        """Test TOTP setup."""
        auth_service = AuthService(db_session)

        secret, uri, qr_code = auth_service.setup_totp(test_user)

        assert secret is not None
        assert len(secret) == 32
        assert "otpauth://" in uri
        assert len(qr_code) > 100  # Base64 encoded PNG

    @pytest.mark.asyncio
    async def test_verify_and_enable_totp(self, db_session, test_user):
        """Test enabling TOTP."""
        import pyotp

        auth_service = AuthService(db_session)

        # Setup
        secret, _, _ = auth_service.setup_totp(test_user)
        await db_session.flush()

        # Get valid code
        totp = pyotp.TOTP(secret)
        code = totp.now()

        # Enable
        result = auth_service.verify_and_enable_totp(test_user, code)

        assert result is True
        assert test_user.totp_enabled is True

    @pytest.mark.asyncio
    async def test_verify_totp_invalid_code(self, db_session, test_user):
        """Test TOTP verification with invalid code."""
        auth_service = AuthService(db_session)

        # Setup
        auth_service.setup_totp(test_user)
        await db_session.flush()

        # Try invalid code
        result = auth_service.verify_and_enable_totp(test_user, "000000")

        assert result is False

    @pytest.mark.asyncio
    async def test_create_recovery_codes(self, db_session, test_user):
        """Test creating recovery codes."""
        auth_service = AuthService(db_session)

        codes = await auth_service.create_recovery_codes(test_user)

        assert len(codes) == 8
        assert all("-" in code for code in codes)


class TestAuthServiceLogout:
    """Tests for logout methods."""

    @pytest.mark.asyncio
    async def test_logout_all_sessions(self, db_session, test_user):
        """Test logging out all sessions."""
        auth_service = AuthService(db_session)

        initial_version = test_user.token_version

        await auth_service.logout_all_sessions(test_user)

        assert test_user.token_version == initial_version + 1
