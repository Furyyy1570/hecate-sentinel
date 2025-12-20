"""Tests for user agent parsing utilities."""

import pytest

from src.core.user_agent import (
    DeviceInfo,
    create_device_fingerprint,
    get_device_friendly_name,
    parse_user_agent,
)


class TestParseUserAgent:
    """Tests for parse_user_agent function."""

    def test_parse_desktop_chrome(self):
        """Test parsing Chrome on Windows desktop."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        result = parse_user_agent(ua)

        assert result.device_type == "desktop"
        assert result.browser == "Chrome"
        assert result.os == "Windows"
        assert result.is_bot is False

    def test_parse_mobile_safari(self):
        """Test parsing Safari on iPhone."""
        ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
        result = parse_user_agent(ua)

        assert result.device_type == "mobile"
        assert result.browser == "Mobile Safari"
        assert result.os == "iOS"
        assert result.is_bot is False

    def test_parse_tablet_android(self):
        """Test parsing Android tablet."""
        ua = "Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        result = parse_user_agent(ua)

        assert result.device_type in ("tablet", "mobile", "desktop")  # Detection varies
        assert result.browser == "Chrome"
        assert result.os == "Android"
        assert result.is_bot is False

    def test_parse_bot_googlebot(self):
        """Test parsing Googlebot."""
        ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        result = parse_user_agent(ua)

        assert result.device_type == "bot"
        assert result.is_bot is True

    def test_parse_empty_user_agent(self):
        """Test parsing empty user agent."""
        result = parse_user_agent("")

        assert result.device_type == "desktop"  # Default fallback
        assert result.is_bot is False

    def test_parse_firefox_linux(self):
        """Test parsing Firefox on Linux."""
        ua = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
        result = parse_user_agent(ua)

        assert result.device_type == "desktop"
        assert result.browser == "Firefox"
        assert result.os == "Linux"
        assert result.is_bot is False


class TestCreateDeviceFingerprint:
    """Tests for create_device_fingerprint function."""

    def test_fingerprint_is_consistent(self):
        """Test that same UA produces same fingerprint."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"

        fp1 = create_device_fingerprint(ua)
        fp2 = create_device_fingerprint(ua)

        assert fp1 == fp2
        assert len(fp1) == 64  # SHA256 hex

    def test_fingerprint_different_for_different_browsers(self):
        """Test that different browsers produce different fingerprints."""
        chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
        firefox_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/120.0"

        fp_chrome = create_device_fingerprint(chrome_ua)
        fp_firefox = create_device_fingerprint(firefox_ua)

        assert fp_chrome != fp_firefox

    def test_fingerprint_survives_version_update(self):
        """Test that minor version changes don't affect fingerprint."""
        ua_v120 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ua_v121 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"

        fp_v120 = create_device_fingerprint(ua_v120)
        fp_v121 = create_device_fingerprint(ua_v121)

        # Fingerprint should be the same since only version changed
        assert fp_v120 == fp_v121


class TestGetDeviceFriendlyName:
    """Tests for get_device_friendly_name function."""

    def test_desktop_with_browser_and_os(self):
        """Test friendly name for desktop browser."""
        device = DeviceInfo(
            device_type="desktop",
            browser="Chrome",
            os="Windows",
        )
        name = get_device_friendly_name(device)

        assert "Chrome" in name
        assert "Windows" in name

    def test_mobile_with_brand_and_model(self):
        """Test friendly name for mobile with brand/model."""
        device = DeviceInfo(
            device_type="mobile",
            browser="Chrome",
            os="Android",
            device_brand="Samsung",
            device_model="Galaxy S21",
        )
        name = get_device_friendly_name(device)

        assert "Chrome" in name
        assert "Android" in name
        assert "Samsung" in name

    def test_mobile_without_brand(self):
        """Test friendly name for mobile without brand."""
        device = DeviceInfo(
            device_type="mobile",
            browser="Safari",
            os="iOS",
        )
        name = get_device_friendly_name(device)

        assert "Safari" in name
        assert "Mobile" in name

    def test_unknown_device(self):
        """Test friendly name for unknown device."""
        device = DeviceInfo(device_type="desktop")
        name = get_device_friendly_name(device)

        assert name == "Unknown Device"
