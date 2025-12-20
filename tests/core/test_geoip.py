"""Tests for GeoIP utilities."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.core.geoip import (
    GeoLocation,
    _is_private_ip,
    create_location_fingerprint,
    get_geolocation,
)


class TestIsPrivateIp:
    """Tests for _is_private_ip function."""

    def test_localhost_ipv4(self):
        """Test localhost is private."""
        assert _is_private_ip("127.0.0.1") is True

    def test_localhost_ipv6(self):
        """Test IPv6 localhost is private."""
        assert _is_private_ip("::1") is True

    def test_private_class_a(self):
        """Test Class A private IP."""
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("10.255.255.255") is True

    def test_private_class_b(self):
        """Test Class B private IP."""
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("172.31.255.255") is True

    def test_private_class_c(self):
        """Test Class C private IP."""
        assert _is_private_ip("192.168.0.1") is True
        assert _is_private_ip("192.168.255.255") is True

    def test_public_ip(self):
        """Test public IP is not private."""
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("1.1.1.1") is False

    def test_invalid_ip(self):
        """Test invalid IP returns True (safe default)."""
        assert _is_private_ip("not.an.ip") is True
        assert _is_private_ip("") is True


class TestGetGeolocation:
    """Tests for get_geolocation function."""

    @pytest.mark.asyncio
    async def test_private_ip_returns_empty(self):
        """Test that private IPs return empty GeoLocation."""
        result = await get_geolocation("192.168.1.1")

        assert isinstance(result, GeoLocation)
        assert result.country is None
        assert result.city is None

    @pytest.mark.asyncio
    async def test_localhost_returns_empty(self):
        """Test that localhost returns empty GeoLocation."""
        result = await get_geolocation("127.0.0.1")

        assert isinstance(result, GeoLocation)
        assert result.country is None

    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        """Test successful geolocation lookup."""
        mock_response_data = {
            "status": "success",
            "country": "United States",
            "countryCode": "US",
            "regionName": "California",
            "city": "San Francisco",
            "lat": 37.7749,
            "lon": -122.4194,
            "timezone": "America/Los_Angeles",
            "isp": "Google LLC",
        }

        # Create a proper mock response object
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_response_data

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client_class.return_value.__aenter__.return_value = mock_client

            result = await get_geolocation("8.8.8.8")

            assert result.country == "United States"
            assert result.country_code == "US"
            assert result.city == "San Francisco"
            assert result.latitude == 37.7749
            assert result.longitude == -122.4194
            assert result.isp == "Google LLC"

    @pytest.mark.asyncio
    async def test_api_failure(self):
        """Test handling API failure."""
        mock_response_data = {
            "status": "fail",
            "message": "reserved range",
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_response_data

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client_class.return_value.__aenter__.return_value = mock_client

            result = await get_geolocation("8.8.8.8")

            assert isinstance(result, GeoLocation)
            assert result.country is None

    @pytest.mark.asyncio
    async def test_http_error(self):
        """Test handling HTTP error."""
        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client_class.return_value.__aenter__.return_value = mock_client

            result = await get_geolocation("8.8.8.8")

            assert isinstance(result, GeoLocation)
            assert result.country is None

    @pytest.mark.asyncio
    async def test_timeout(self):
        """Test handling timeout."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.side_effect = httpx.TimeoutException("timeout")
            mock_client_class.return_value.__aenter__.return_value = mock_client

            result = await get_geolocation("8.8.8.8")

            assert isinstance(result, GeoLocation)
            assert result.country is None


class TestCreateLocationFingerprint:
    """Tests for create_location_fingerprint function."""

    def test_fingerprint_is_consistent(self):
        """Test that same location produces same fingerprint."""
        fp1 = create_location_fingerprint("United States", "San Francisco")
        fp2 = create_location_fingerprint("United States", "San Francisco")

        assert fp1 == fp2
        assert len(fp1) == 64  # SHA256 hex

    def test_fingerprint_different_for_different_locations(self):
        """Test that different locations produce different fingerprints."""
        fp1 = create_location_fingerprint("United States", "San Francisco")
        fp2 = create_location_fingerprint("United States", "Los Angeles")

        assert fp1 != fp2

    def test_fingerprint_case_insensitive(self):
        """Test that fingerprint is case-insensitive."""
        fp1 = create_location_fingerprint("United States", "San Francisco")
        fp2 = create_location_fingerprint("UNITED STATES", "SAN FRANCISCO")

        assert fp1 == fp2

    def test_fingerprint_handles_none(self):
        """Test fingerprint with None values."""
        fp = create_location_fingerprint(None, None)

        assert isinstance(fp, str)
        assert len(fp) == 64

    def test_fingerprint_partial_none(self):
        """Test fingerprint with partial None values."""
        fp1 = create_location_fingerprint("United States", None)
        fp2 = create_location_fingerprint(None, "San Francisco")

        assert fp1 != fp2
        assert len(fp1) == 64
        assert len(fp2) == 64


class TestGeoLocation:
    """Tests for GeoLocation dataclass."""

    def test_default_values(self):
        """Test GeoLocation default values."""
        geo = GeoLocation()

        assert geo.country is None
        assert geo.country_code is None
        assert geo.region is None
        assert geo.city is None
        assert geo.latitude is None
        assert geo.longitude is None
        assert geo.timezone is None
        assert geo.isp is None

    def test_with_values(self):
        """Test GeoLocation with values."""
        geo = GeoLocation(
            country="United States",
            country_code="US",
            city="San Francisco",
            latitude=37.7749,
            longitude=-122.4194,
        )

        assert geo.country == "United States"
        assert geo.country_code == "US"
        assert geo.city == "San Francisco"
        assert geo.latitude == 37.7749
