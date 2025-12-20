"""Tests for authentication API endpoints."""

from unittest.mock import AsyncMock, patch

import pytest

from src.core.geoip import GeoLocation


class TestAuthRegister:
    """Tests for POST /auth/register."""

    @pytest.mark.asyncio
    async def test_register_success(self, client):
        """Test successful user registration."""
        with patch("src.api.auth.email_sender") as mock_email:
            mock_email.send_verification_email = AsyncMock()

            response = await client.post(
                "/auth/register",
                json={
                    "username": "newuser",
                    "email": "newuser@example.com",
                    "password": "SecurePass123!",
                },
            )

            assert response.status_code == 201
            data = response.json()
            assert "message" in data
            assert "verify" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_register_duplicate_username(self, client, test_user):
        """Test registration with existing username."""
        response = await client.post(
            "/auth/register",
            json={
                "username": test_user.username,
                "email": "different@example.com",
                "password": "SecurePass123!",
            },
        )

        assert response.status_code == 409
        assert "username" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_register_duplicate_email(self, client, verified_user):
        """Test registration with existing email."""
        response = await client.post(
            "/auth/register",
            json={
                "username": "differentuser",
                "email": "test@example.com",
                "password": "SecurePass123!",
            },
        )

        assert response.status_code == 409
        assert "email" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_register_disabled(self, client):
        """Test registration when disabled."""
        with patch("src.api.auth.settings") as mock_settings:
            mock_settings.allow_registration = False

            response = await client.post(
                "/auth/register",
                json={
                    "username": "newuser",
                    "email": "new@example.com",
                    "password": "SecurePass123!",
                },
            )

            assert response.status_code == 403
            assert "disabled" in response.json()["detail"].lower()


class TestAuthLogin:
    """Tests for POST /auth/login."""

    @pytest.mark.asyncio
    async def test_login_success(self, client, verified_user):
        """Test successful login with verified email."""
        mock_geo = GeoLocation(country="US", city="NYC")

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            with patch("src.api.auth.email_sender") as mock_email:
                mock_email.send_new_device_alert = AsyncMock()
                mock_email.send_new_location_alert = AsyncMock()

                response = await client.post(
                    "/auth/login",
                    json={
                        "login": verified_user.username,
                        "password": "testpassword123",
                    },
                )

                assert response.status_code == 200
                data = response.json()
                assert "access_token" in data
                assert "refresh_token" in data
                assert data["token_type"] == "bearer"

    @pytest.mark.asyncio
    async def test_login_by_email(self, client, verified_user):
        """Test login with email instead of username."""
        mock_geo = GeoLocation(country="US", city="NYC")

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            with patch("src.api.auth.email_sender") as mock_email:
                mock_email.send_new_device_alert = AsyncMock()
                mock_email.send_new_location_alert = AsyncMock()

                response = await client.post(
                    "/auth/login",
                    json={
                        "login": "test@example.com",
                        "password": "testpassword123",
                    },
                )

                assert response.status_code == 200
                assert "access_token" in response.json()

    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, client, verified_user):
        """Test login with wrong password."""
        response = await client.post(
            "/auth/login",
            json={
                "login": verified_user.username,
                "password": "wrongpassword",
            },
        )

        assert response.status_code == 401
        assert "invalid" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_login_user_not_found(self, client):
        """Test login with non-existent user."""
        response = await client.post(
            "/auth/login",
            json={
                "login": "nonexistent",
                "password": "password123",
            },
        )

        assert response.status_code == 401
        assert "invalid" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_login_unverified_email(self, client, test_user):
        """Test login with unverified email."""
        response = await client.post(
            "/auth/login",
            json={
                "login": test_user.username,
                "password": "testpassword123",
            },
        )

        assert response.status_code == 403
        assert "verification" in response.json()["detail"].lower()


class TestAuthVerifyEmail:
    """Tests for POST /auth/verify-email."""

    @pytest.mark.asyncio
    async def test_verify_email_success(self, client, db_session):
        """Test successful email verification."""
        from src.services.auth import AuthService

        auth_service = AuthService(db_session)

        # Register user to get token
        with patch("src.api.auth.email_sender") as mock_email:
            mock_email.send_verification_email = AsyncMock()

            await client.post(
                "/auth/register",
                json={
                    "username": "verifytest",
                    "email": "verifytest@example.com",
                    "password": "SecurePass123!",
                },
            )

        # Get the token from the database
        user = await auth_service.get_user_by_username("verifytest")
        primary_email = await auth_service.get_unverified_primary_email(user)
        token = await auth_service.create_email_verification_token(primary_email)
        await db_session.commit()

        response = await client.post(
            "/auth/verify-email",
            json={"token": token},
        )

        assert response.status_code == 200
        assert "verified" in response.json()["message"].lower()

    @pytest.mark.asyncio
    async def test_verify_email_invalid_token(self, client):
        """Test email verification with invalid token."""
        response = await client.post(
            "/auth/verify-email",
            json={"token": "invalid_token_that_is_long_enough_to_be_valid"},
        )

        assert response.status_code == 400
        assert "invalid" in response.json()["detail"].lower()


class TestAuthRefreshToken:
    """Tests for POST /auth/refresh."""

    @pytest.mark.asyncio
    async def test_refresh_token_success(self, client, verified_user):
        """Test successful token refresh."""
        mock_geo = GeoLocation(country="US", city="NYC")

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            with patch("src.api.auth.email_sender") as mock_email:
                mock_email.send_new_device_alert = AsyncMock()
                mock_email.send_new_location_alert = AsyncMock()

                # First login to get tokens
                login_response = await client.post(
                    "/auth/login",
                    json={
                        "login": verified_user.username,
                        "password": "testpassword123",
                    },
                )
                tokens = login_response.json()

                # Refresh
                response = await client.post(
                    "/auth/refresh",
                    json={"refresh_token": tokens["refresh_token"]},
                )

                assert response.status_code == 200
                data = response.json()
                assert "access_token" in data
                assert "refresh_token" in data

    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, client):
        """Test refresh with invalid token."""
        response = await client.post(
            "/auth/refresh",
            json={"refresh_token": "invalid_token"},
        )

        assert response.status_code == 401
        assert "invalid" in response.json()["detail"].lower()


class TestAuthPasswordReset:
    """Tests for password reset endpoints."""

    @pytest.mark.asyncio
    async def test_request_password_reset(self, client, verified_user):
        """Test requesting password reset."""
        with patch("src.api.auth.email_sender") as mock_email:
            mock_email.send_password_reset_email = AsyncMock()

            response = await client.post(
                "/auth/password-reset/request",
                json={"email": "test@example.com"},
            )

            assert response.status_code == 200
            # Always returns success to prevent enumeration

    @pytest.mark.asyncio
    async def test_request_password_reset_unknown_email(self, client):
        """Test password reset for unknown email."""
        response = await client.post(
            "/auth/password-reset/request",
            json={"email": "unknown@example.com"},
        )

        # Should still return 200 to prevent enumeration
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_confirm_password_reset(self, client, db_session, verified_user):
        """Test confirming password reset."""
        from src.services.auth import AuthService

        auth_service = AuthService(db_session)

        # Create reset token
        result = await auth_service.create_password_reset_token("test@example.com")
        assert result is not None
        _, token = result
        await db_session.commit()

        response = await client.post(
            "/auth/password-reset/confirm",
            json={
                "token": token,
                "new_password": "NewSecurePass123!",
            },
        )

        assert response.status_code == 200
        assert "reset" in response.json()["message"].lower()

    @pytest.mark.asyncio
    async def test_confirm_password_reset_invalid_token(self, client):
        """Test password reset with invalid token."""
        response = await client.post(
            "/auth/password-reset/confirm",
            json={
                "token": "invalid_token_that_is_long_enough_to_be_valid",
                "new_password": "NewSecurePass123!",
            },
        )

        assert response.status_code == 400
        assert "invalid" in response.json()["detail"].lower()


class TestAuthChangePassword:
    """Tests for POST /auth/change-password."""

    @pytest.mark.asyncio
    async def test_change_password_success(self, client, verified_user):
        """Test successful password change."""
        mock_geo = GeoLocation(country="US", city="NYC")

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            with patch("src.api.auth.email_sender") as mock_email:
                mock_email.send_new_device_alert = AsyncMock()
                mock_email.send_new_location_alert = AsyncMock()

                # Login first
                login_response = await client.post(
                    "/auth/login",
                    json={
                        "login": verified_user.username,
                        "password": "testpassword123",
                    },
                )
                tokens = login_response.json()

                # Change password
                response = await client.post(
                    "/auth/change-password",
                    json={
                        "current_password": "testpassword123",
                        "new_password": "NewSecurePass123!",
                    },
                    headers={"Authorization": f"Bearer {tokens['access_token']}"},
                )

                assert response.status_code == 200
                assert "changed" in response.json()["message"].lower()

    @pytest.mark.asyncio
    async def test_change_password_wrong_current(self, client, verified_user):
        """Test password change with wrong current password."""
        mock_geo = GeoLocation(country="US", city="NYC")

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            with patch("src.api.auth.email_sender") as mock_email:
                mock_email.send_new_device_alert = AsyncMock()
                mock_email.send_new_location_alert = AsyncMock()

                # Login first
                login_response = await client.post(
                    "/auth/login",
                    json={
                        "login": verified_user.username,
                        "password": "testpassword123",
                    },
                )
                tokens = login_response.json()

                # Try to change with wrong current password
                response = await client.post(
                    "/auth/change-password",
                    json={
                        "current_password": "wrongpassword",
                        "new_password": "NewSecurePass123!",
                    },
                    headers={"Authorization": f"Bearer {tokens['access_token']}"},
                )

                assert response.status_code == 400
                assert "incorrect" in response.json()["detail"].lower()


class TestAuthMe:
    """Tests for GET /auth/me."""

    @pytest.mark.asyncio
    async def test_get_current_user(self, client, verified_user):
        """Test getting current user info."""
        mock_geo = GeoLocation(country="US", city="NYC")

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            with patch("src.api.auth.email_sender") as mock_email:
                mock_email.send_new_device_alert = AsyncMock()
                mock_email.send_new_location_alert = AsyncMock()

                # Login first
                login_response = await client.post(
                    "/auth/login",
                    json={
                        "login": verified_user.username,
                        "password": "testpassword123",
                    },
                )
                tokens = login_response.json()

                # Get user info
                response = await client.get(
                    "/auth/me",
                    headers={"Authorization": f"Bearer {tokens['access_token']}"},
                )

                assert response.status_code == 200
                data = response.json()
                assert data["username"] == verified_user.username
                assert data["email"] == "test@example.com"
                assert data["email_verified"] is True

    @pytest.mark.asyncio
    async def test_get_current_user_unauthorized(self, client):
        """Test getting user info without auth."""
        response = await client.get("/auth/me")

        # HTTPBearer returns 401 or 403 without token depending on version
        assert response.status_code in [401, 403]


class TestAuthLogoutAll:
    """Tests for POST /auth/logout-all."""

    @pytest.mark.asyncio
    async def test_logout_all_sessions(self, client, verified_user):
        """Test logging out all sessions."""
        mock_geo = GeoLocation(country="US", city="NYC")

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            with patch("src.api.auth.email_sender") as mock_email:
                mock_email.send_new_device_alert = AsyncMock()
                mock_email.send_new_location_alert = AsyncMock()

                # Login first
                login_response = await client.post(
                    "/auth/login",
                    json={
                        "login": verified_user.username,
                        "password": "testpassword123",
                    },
                )
                tokens = login_response.json()

                # Logout all
                response = await client.post(
                    "/auth/logout-all",
                    headers={"Authorization": f"Bearer {tokens['access_token']}"},
                )

                assert response.status_code == 200
                assert "logged out" in response.json()["message"].lower()


class TestAuthMagicLink:
    """Tests for magic link endpoints."""

    @pytest.mark.asyncio
    async def test_request_magic_link(self, client, verified_user):
        """Test requesting magic link."""
        with patch("src.api.auth.email_sender") as mock_email:
            mock_email.send_magic_link_email = AsyncMock()

            response = await client.post(
                "/auth/magic-link/request",
                json={"email": "test@example.com"},
            )

            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_request_magic_link_unknown_email(self, client):
        """Test magic link for unknown email."""
        response = await client.post(
            "/auth/magic-link/request",
            json={"email": "unknown@example.com"},
        )

        # Should still return 200 to prevent enumeration
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_verify_magic_link(self, client, db_session, verified_user):
        """Test verifying magic link."""
        from src.services.auth import AuthService

        mock_geo = GeoLocation(country="US", city="NYC")

        auth_service = AuthService(db_session)
        result = await auth_service.create_magic_link("test@example.com")
        assert result is not None
        _, token = result
        await db_session.commit()

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            with patch("src.api.auth.email_sender") as mock_email:
                mock_email.send_new_device_alert = AsyncMock()
                mock_email.send_new_location_alert = AsyncMock()

                response = await client.post(
                    "/auth/magic-link/verify",
                    json={"token": token},
                )

                assert response.status_code == 200
                data = response.json()
                assert "access_token" in data
                assert "refresh_token" in data

    @pytest.mark.asyncio
    async def test_verify_magic_link_invalid(self, client):
        """Test verifying invalid magic link."""
        response = await client.post(
            "/auth/magic-link/verify",
            json={"token": "invalid_token_that_is_long_enough_to_be_valid"},
        )

        assert response.status_code == 400
        assert "invalid" in response.json()["detail"].lower()


class TestAuthOAuth:
    """Tests for OAuth endpoints."""

    @pytest.mark.asyncio
    async def test_list_oauth_providers(self, client):
        """Test listing OAuth providers."""
        response = await client.get("/auth/oauth/providers")

        assert response.status_code == 200
        data = response.json()
        assert "providers" in data
        assert len(data["providers"]) > 0

    @pytest.mark.asyncio
    async def test_oauth_authorize_unknown_provider(self, client):
        """Test OAuth authorize with unknown provider."""
        response = await client.get("/auth/oauth/unknown/authorize")

        assert response.status_code == 400
        assert "unknown" in response.json()["detail"].lower()
