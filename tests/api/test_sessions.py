"""Tests for sessions API endpoints."""

from unittest.mock import AsyncMock, patch

import pytest

from src.core.geoip import GeoLocation


class TestSessionsListSessions:
    """Tests for GET /sessions."""

    @pytest.mark.asyncio
    async def test_list_sessions(self, client, verified_user):
        """Test listing active sessions."""
        mock_geo = GeoLocation(country="US", city="NYC")

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            with patch("src.api.auth.email_sender") as mock_email:
                mock_email.send_new_device_alert = AsyncMock()
                mock_email.send_new_location_alert = AsyncMock()

                # Login to create a session
                login_response = await client.post(
                    "/auth/login",
                    json={
                        "login": verified_user.username,
                        "password": "testpassword123",
                    },
                )
                tokens = login_response.json()

                # List sessions
                response = await client.get(
                    "/sessions",
                    headers={
                        "Authorization": f"Bearer {tokens['access_token']}",
                        "x-refresh-token": tokens["refresh_token"],
                    },
                )

                assert response.status_code == 200
                data = response.json()
                assert "sessions" in data
                assert "total" in data
                assert data["total"] >= 1

    @pytest.mark.asyncio
    async def test_list_sessions_unauthorized(self, client):
        """Test listing sessions without auth."""
        response = await client.get("/sessions")

        assert response.status_code in [401, 403]


class TestSessionsRevokeSession:
    """Tests for DELETE /sessions/{session_uuid}."""

    @pytest.mark.asyncio
    async def test_revoke_session(self, client, verified_user):
        """Test revoking a specific session."""
        mock_geo = GeoLocation(country="US", city="NYC")

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            with patch("src.api.auth.email_sender") as mock_email:
                mock_email.send_new_device_alert = AsyncMock()
                mock_email.send_new_location_alert = AsyncMock()

                # Login to create sessions
                login1 = await client.post(
                    "/auth/login",
                    json={
                        "login": verified_user.username,
                        "password": "testpassword123",
                    },
                )
                tokens1 = login1.json()

                # Get sessions to find session UUID
                sessions_response = await client.get(
                    "/sessions",
                    headers={
                        "Authorization": f"Bearer {tokens1['access_token']}",
                    },
                )
                sessions = sessions_response.json()["sessions"]

                # Revoke the first session
                if sessions:
                    response = await client.delete(
                        f"/sessions/{sessions[0]['uuid']}",
                        headers={
                            "Authorization": f"Bearer {tokens1['access_token']}",
                        },
                    )

                    assert response.status_code == 200
                    assert "revoked" in response.json()["message"].lower()

    @pytest.mark.asyncio
    async def test_revoke_session_not_found(self, client, verified_user):
        """Test revoking non-existent session."""
        mock_geo = GeoLocation(country="US", city="NYC")

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            with patch("src.api.auth.email_sender") as mock_email:
                mock_email.send_new_device_alert = AsyncMock()
                mock_email.send_new_location_alert = AsyncMock()

                login_response = await client.post(
                    "/auth/login",
                    json={
                        "login": verified_user.username,
                        "password": "testpassword123",
                    },
                )
                tokens = login_response.json()

                response = await client.delete(
                    "/sessions/00000000-0000-0000-0000-000000000000",
                    headers={
                        "Authorization": f"Bearer {tokens['access_token']}",
                    },
                )

                assert response.status_code == 404


class TestSessionsRevokeAllSessions:
    """Tests for DELETE /sessions."""

    @pytest.mark.asyncio
    async def test_revoke_all_sessions(self, client, verified_user):
        """Test revoking all sessions."""
        mock_geo = GeoLocation(country="US", city="NYC")

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            with patch("src.api.auth.email_sender") as mock_email:
                mock_email.send_new_device_alert = AsyncMock()
                mock_email.send_new_location_alert = AsyncMock()

                # Login to create session
                login_response = await client.post(
                    "/auth/login",
                    json={
                        "login": verified_user.username,
                        "password": "testpassword123",
                    },
                )
                tokens = login_response.json()

                # Revoke all
                response = await client.delete(
                    "/sessions?keep_current=false",
                    headers={
                        "Authorization": f"Bearer {tokens['access_token']}",
                    },
                )

                assert response.status_code == 200
                assert "revoked" in response.json()["message"].lower()

    @pytest.mark.asyncio
    async def test_revoke_all_sessions_keep_current(self, client, verified_user):
        """Test revoking all sessions except current."""
        mock_geo = GeoLocation(country="US", city="NYC")

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            with patch("src.api.auth.email_sender") as mock_email:
                mock_email.send_new_device_alert = AsyncMock()
                mock_email.send_new_location_alert = AsyncMock()

                # Login to create session
                login_response = await client.post(
                    "/auth/login",
                    json={
                        "login": verified_user.username,
                        "password": "testpassword123",
                    },
                )
                tokens = login_response.json()

                # Revoke all except current
                response = await client.delete(
                    "/sessions?keep_current=true",
                    headers={
                        "Authorization": f"Bearer {tokens['access_token']}",
                        "x-refresh-token": tokens["refresh_token"],
                    },
                )

                assert response.status_code == 200
