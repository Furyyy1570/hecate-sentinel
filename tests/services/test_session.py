"""Tests for SessionService."""

import hashlib
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from src.core.geoip import GeoLocation
from src.core.request_context import RequestContext
from src.core.user_agent import DeviceInfo
from src.models.known_device import KnownDevice
from src.models.known_location import KnownLocation
from src.models.session import UserSession
from src.services.session import SessionService


@pytest.fixture
def mock_geo():
    """Mock geolocation response."""
    return GeoLocation(
        country="United States",
        country_code="US",
        region="California",
        city="San Francisco",
        latitude=37.7749,
        longitude=-122.4194,
        timezone="America/Los_Angeles",
        isp="Test ISP",
    )


class TestSessionServiceCreateSession:
    """Tests for SessionService.create_session method."""

    @pytest.mark.asyncio
    async def test_create_session(self, db_session, test_user, request_context, mock_geo):
        """Test creating a new session."""
        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            session_service = SessionService(db_session)

            user_session, is_new_device, is_new_location, geo, device_info = (
                await session_service.create_session(
                    test_user,
                    "test_refresh_token",
                    request_context,
                )
            )

            assert user_session.id is not None
            assert user_session.user_id == test_user.id
            assert user_session.ip_address == request_context.ip_address
            assert is_new_device is True  # First time = new device
            assert is_new_location is True  # First time = new location
            assert geo.country == "United States"
            assert device_info is not None

    @pytest.mark.asyncio
    async def test_create_session_existing_device(
        self, db_session, test_user, request_context, mock_geo
    ):
        """Test that second session from same device is not flagged as new."""
        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            session_service = SessionService(db_session)

            # First session
            _, is_new_device1, _, _, _ = await session_service.create_session(
                test_user,
                "token1",
                request_context,
            )
            await db_session.flush()

            # Second session from same device
            _, is_new_device2, _, _, _ = await session_service.create_session(
                test_user,
                "token2",
                request_context,
            )

            assert is_new_device1 is True
            assert is_new_device2 is False

    @pytest.mark.asyncio
    async def test_create_session_existing_location(
        self, db_session, test_user, request_context, mock_geo
    ):
        """Test that second session from same location is not flagged as new."""
        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            session_service = SessionService(db_session)

            # First session
            _, _, is_new_location1, _, _ = await session_service.create_session(
                test_user,
                "token1",
                request_context,
            )
            await db_session.flush()

            # Second session from same location
            _, _, is_new_location2, _, _ = await session_service.create_session(
                test_user,
                "token2",
                request_context,
            )

            assert is_new_location1 is True
            assert is_new_location2 is False

    @pytest.mark.asyncio
    async def test_create_session_no_location_data(self, db_session, test_user, request_context):
        """Test session creation when geolocation returns no data."""
        empty_geo = GeoLocation()
        with patch("src.services.session.get_geolocation", return_value=empty_geo):
            session_service = SessionService(db_session)

            _, _, is_new_location, geo, _ = await session_service.create_session(
                test_user,
                "token1",
                request_context,
            )

            assert is_new_location is False  # No location = not new
            assert geo.country is None


class TestSessionServiceGetActiveSessions:
    """Tests for SessionService.get_active_sessions method."""

    @pytest.mark.asyncio
    async def test_get_active_sessions_empty(self, db_session, test_user):
        """Test getting sessions when none exist."""
        session_service = SessionService(db_session)

        sessions = await session_service.get_active_sessions(test_user)

        assert sessions == []

    @pytest.mark.asyncio
    async def test_get_active_sessions(self, db_session, test_user, request_context, mock_geo):
        """Test getting active sessions."""
        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            session_service = SessionService(db_session)

            # Create sessions
            await session_service.create_session(test_user, "token1", request_context)
            await session_service.create_session(test_user, "token2", request_context)
            await db_session.flush()

            sessions = await session_service.get_active_sessions(test_user)

            assert len(sessions) == 2

    @pytest.mark.asyncio
    async def test_get_active_sessions_marks_current(
        self, db_session, test_user, request_context, mock_geo
    ):
        """Test that current session is marked correctly."""
        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            session_service = SessionService(db_session)

            user_session, _, _, _, _ = await session_service.create_session(
                test_user, "token1", request_context
            )
            await db_session.flush()

            token_hash = hashlib.sha256("token1".encode()).hexdigest()
            sessions = await session_service.get_active_sessions(
                test_user, current_token_hash=token_hash
            )

            assert len(sessions) == 1
            session, is_current = sessions[0]
            assert is_current is True


class TestSessionServiceRevokeSession:
    """Tests for SessionService.revoke_session method."""

    @pytest.mark.asyncio
    async def test_revoke_session(self, db_session, test_user, request_context, mock_geo):
        """Test revoking a session."""
        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            session_service = SessionService(db_session)

            user_session, _, _, _, _ = await session_service.create_session(
                test_user, "token1", request_context
            )
            await db_session.flush()

            result = await session_service.revoke_session(
                test_user, str(user_session.uuid)
            )

            assert result is True
            assert user_session.revoked_at is not None

    @pytest.mark.asyncio
    async def test_revoke_session_not_found(self, db_session, test_user):
        """Test revoking non-existent session."""
        session_service = SessionService(db_session)

        result = await session_service.revoke_session(
            test_user, "00000000-0000-0000-0000-000000000000"
        )

        assert result is False


class TestSessionServiceRevokeAllSessions:
    """Tests for SessionService.revoke_all_sessions method."""

    @pytest.mark.asyncio
    async def test_revoke_all_sessions(
        self, db_session, test_user, request_context, mock_geo
    ):
        """Test revoking all sessions."""
        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            session_service = SessionService(db_session)

            # Create multiple sessions
            await session_service.create_session(test_user, "token1", request_context)
            await session_service.create_session(test_user, "token2", request_context)
            await session_service.create_session(test_user, "token3", request_context)
            await db_session.flush()

            count = await session_service.revoke_all_sessions(test_user)

            assert count == 3

    @pytest.mark.asyncio
    async def test_revoke_all_sessions_except_current(
        self, db_session, test_user, request_context, mock_geo
    ):
        """Test revoking all sessions except current."""
        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            session_service = SessionService(db_session)

            # Create sessions
            await session_service.create_session(test_user, "token1", request_context)
            await session_service.create_session(test_user, "token2", request_context)
            await db_session.flush()

            current_hash = hashlib.sha256("token1".encode()).hexdigest()
            count = await session_service.revoke_all_sessions(
                test_user, except_token_hash=current_hash
            )

            assert count == 1  # Only token2 revoked


class TestSessionServiceValidateSession:
    """Tests for SessionService.validate_session method."""

    @pytest.mark.asyncio
    async def test_validate_session_valid(
        self, db_session, test_user, request_context, mock_geo
    ):
        """Test validating a valid session."""
        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            session_service = SessionService(db_session)

            await session_service.create_session(test_user, "token1", request_context)
            await db_session.flush()

            result = await session_service.validate_session("token1")

            assert result is not None
            assert result.user_id == test_user.id

    @pytest.mark.asyncio
    async def test_validate_session_invalid_token(self, db_session):
        """Test validating invalid token."""
        session_service = SessionService(db_session)

        result = await session_service.validate_session("invalid_token")

        assert result is None

    @pytest.mark.asyncio
    async def test_validate_session_revoked(
        self, db_session, test_user, request_context, mock_geo
    ):
        """Test validating revoked session."""
        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            session_service = SessionService(db_session)

            user_session, _, _, _, _ = await session_service.create_session(
                test_user, "token1", request_context
            )
            await db_session.flush()

            # Revoke the session
            await session_service.revoke_session(test_user, str(user_session.uuid))

            result = await session_service.validate_session("token1")

            assert result is None


class TestSessionServiceKnownDevicesLocations:
    """Tests for known devices and locations methods."""

    @pytest.mark.asyncio
    async def test_get_known_devices(
        self, db_session, test_user, request_context, mock_geo
    ):
        """Test getting known devices."""
        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            session_service = SessionService(db_session)

            await session_service.create_session(test_user, "token1", request_context)
            await db_session.flush()

            devices = await session_service.get_known_devices(test_user)

            assert len(devices) == 1
            assert devices[0].user_id == test_user.id

    @pytest.mark.asyncio
    async def test_get_known_locations(
        self, db_session, test_user, request_context, mock_geo
    ):
        """Test getting known locations."""
        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            session_service = SessionService(db_session)

            await session_service.create_session(test_user, "token1", request_context)
            await db_session.flush()

            locations = await session_service.get_known_locations(test_user)

            assert len(locations) == 1
            assert locations[0].country == "United States"
