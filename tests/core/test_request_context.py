"""Tests for request context utilities."""

from unittest.mock import MagicMock

import pytest

from src.core.request_context import RequestContext, get_request_context, _get_client_ip


class TestGetClientIp:
    """Tests for _get_client_ip function."""

    def test_direct_client_ip(self):
        """Test getting IP from direct client connection."""
        request = MagicMock()
        request.headers = {}
        request.client.host = "192.168.1.100"

        ip = _get_client_ip(request)

        assert ip == "192.168.1.100"

    def test_x_forwarded_for_single(self):
        """Test getting IP from X-Forwarded-For header."""
        request = MagicMock()
        request.headers = {"x-forwarded-for": "203.0.113.50"}
        request.client.host = "10.0.0.1"

        ip = _get_client_ip(request)

        assert ip == "203.0.113.50"

    def test_x_forwarded_for_multiple(self):
        """Test getting first IP from X-Forwarded-For with multiple IPs."""
        request = MagicMock()
        request.headers = {"x-forwarded-for": "203.0.113.50, 198.51.100.1, 10.0.0.1"}
        request.client.host = "10.0.0.1"

        ip = _get_client_ip(request)

        assert ip == "203.0.113.50"

    def test_x_real_ip(self):
        """Test getting IP from X-Real-IP header."""
        request = MagicMock()
        request.headers = {"x-real-ip": "203.0.113.75"}
        request.client.host = "10.0.0.1"

        ip = _get_client_ip(request)

        assert ip == "203.0.113.75"

    def test_x_forwarded_for_takes_precedence(self):
        """Test X-Forwarded-For takes precedence over X-Real-IP."""
        request = MagicMock()
        request.headers = {
            "x-forwarded-for": "203.0.113.50",
            "x-real-ip": "198.51.100.1",
        }
        request.client.host = "10.0.0.1"

        ip = _get_client_ip(request)

        assert ip == "203.0.113.50"

    def test_no_client(self):
        """Test when no client information is available."""
        request = MagicMock()
        request.headers = {}
        request.client = None

        ip = _get_client_ip(request)

        assert ip == "unknown"

    def test_whitespace_handling(self):
        """Test that whitespace is stripped from IPs."""
        request = MagicMock()
        request.headers = {"x-forwarded-for": "  203.0.113.50  "}
        request.client.host = "10.0.0.1"

        ip = _get_client_ip(request)

        assert ip == "203.0.113.50"


class TestGetRequestContext:
    """Tests for get_request_context function."""

    def test_full_context(self):
        """Test extracting full request context."""
        request = MagicMock()
        request.headers = {
            "user-agent": "Mozilla/5.0 Test Browser",
            "x-request-id": "req-123",
            "x-forwarded-for": "203.0.113.50",
        }
        request.client.host = "10.0.0.1"

        context = get_request_context(request)

        assert isinstance(context, RequestContext)
        assert context.ip_address == "203.0.113.50"
        assert context.user_agent == "Mozilla/5.0 Test Browser"
        assert context.request_id == "req-123"

    def test_missing_user_agent(self):
        """Test context with missing user agent."""
        request = MagicMock()
        request.headers = {}
        request.client.host = "192.168.1.1"

        context = get_request_context(request)

        assert context.user_agent == ""

    def test_missing_request_id(self):
        """Test context with missing request ID."""
        request = MagicMock()
        request.headers = {"user-agent": "Test"}
        request.client.host = "192.168.1.1"

        context = get_request_context(request)

        assert context.request_id is None


class TestRequestContext:
    """Tests for RequestContext dataclass."""

    def test_create_context(self):
        """Test creating a RequestContext instance."""
        context = RequestContext(
            ip_address="127.0.0.1",
            user_agent="Test Agent",
            request_id="test-123",
        )

        assert context.ip_address == "127.0.0.1"
        assert context.user_agent == "Test Agent"
        assert context.request_id == "test-123"

    def test_optional_request_id(self):
        """Test RequestContext with optional request_id."""
        context = RequestContext(
            ip_address="127.0.0.1",
            user_agent="Test Agent",
        )

        assert context.request_id is None
