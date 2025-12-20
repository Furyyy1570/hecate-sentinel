"""Tests for security API endpoints."""

from unittest.mock import AsyncMock, patch

import pytest

from src.core.geoip import GeoLocation


class TestSecurityAuditLog:
    """Tests for GET /security/audit-log."""

    @pytest.mark.asyncio
    async def test_get_audit_log(self, client, verified_user, db_session):
        """Test getting audit log."""
        mock_geo = GeoLocation(country="US", city="NYC")

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            with patch("src.api.auth.email_sender") as mock_email:
                mock_email.send_new_device_alert = AsyncMock()
                mock_email.send_new_location_alert = AsyncMock()

                # Login to create audit entries
                login_response = await client.post(
                    "/auth/login",
                    json={
                        "login": verified_user.username,
                        "password": "testpassword123",
                    },
                )
                tokens = login_response.json()

                # Get audit log
                response = await client.get(
                    "/security/audit-log",
                    headers={"Authorization": f"Bearer {tokens['access_token']}"},
                )

                assert response.status_code == 200
                data = response.json()
                assert "logs" in data
                assert "total" in data
                assert "page" in data
                assert "page_size" in data

    @pytest.mark.asyncio
    async def test_get_audit_log_pagination(self, client, verified_user):
        """Test audit log pagination."""
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

                response = await client.get(
                    "/security/audit-log?page=1&page_size=10",
                    headers={"Authorization": f"Bearer {tokens['access_token']}"},
                )

                assert response.status_code == 200
                data = response.json()
                assert data["page"] == 1
                assert data["page_size"] == 10

    @pytest.mark.asyncio
    async def test_get_audit_log_unauthorized(self, client):
        """Test audit log without auth."""
        response = await client.get("/security/audit-log")

        assert response.status_code in [401, 403]


class TestSecurityDevices:
    """Tests for GET /security/devices."""

    @pytest.mark.asyncio
    async def test_get_known_devices(self, client, verified_user):
        """Test getting known devices."""
        mock_geo = GeoLocation(country="US", city="NYC")

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            with patch("src.api.auth.email_sender") as mock_email:
                mock_email.send_new_device_alert = AsyncMock()
                mock_email.send_new_location_alert = AsyncMock()

                # Login to create device entry
                login_response = await client.post(
                    "/auth/login",
                    json={
                        "login": verified_user.username,
                        "password": "testpassword123",
                    },
                )
                tokens = login_response.json()

                # Get devices
                response = await client.get(
                    "/security/devices",
                    headers={"Authorization": f"Bearer {tokens['access_token']}"},
                )

                assert response.status_code == 200
                data = response.json()
                assert "devices" in data
                assert "total" in data

    @pytest.mark.asyncio
    async def test_get_known_devices_unauthorized(self, client):
        """Test getting devices without auth."""
        response = await client.get("/security/devices")

        assert response.status_code in [401, 403]


class TestSecurityLocations:
    """Tests for GET /security/locations."""

    @pytest.mark.asyncio
    async def test_get_known_locations(self, client, verified_user):
        """Test getting known locations."""
        mock_geo = GeoLocation(country="US", city="NYC")

        with patch("src.services.session.get_geolocation", return_value=mock_geo):
            with patch("src.api.auth.email_sender") as mock_email:
                mock_email.send_new_device_alert = AsyncMock()
                mock_email.send_new_location_alert = AsyncMock()

                # Login to create location entry
                login_response = await client.post(
                    "/auth/login",
                    json={
                        "login": verified_user.username,
                        "password": "testpassword123",
                    },
                )
                tokens = login_response.json()

                # Get locations
                response = await client.get(
                    "/security/locations",
                    headers={"Authorization": f"Bearer {tokens['access_token']}"},
                )

                assert response.status_code == 200
                data = response.json()
                assert "locations" in data
                assert "total" in data

    @pytest.mark.asyncio
    async def test_get_known_locations_unauthorized(self, client):
        """Test getting locations without auth."""
        response = await client.get("/security/locations")

        assert response.status_code in [401, 403]
