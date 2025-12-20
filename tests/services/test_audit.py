"""Tests for AuditService."""

from datetime import datetime, timedelta, timezone

import pytest

from src.core.request_context import RequestContext
from src.models.audit_log import AuditEventType, AuditLog
from src.services.audit import AuditService


class TestAuditServiceLogEvent:
    """Tests for AuditService.log_event method."""

    @pytest.mark.asyncio
    async def test_log_event_minimal(self, db_session):
        """Test logging event with minimal data."""
        audit_service = AuditService(db_session)

        log = await audit_service.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
        )

        assert log.id is not None
        assert log.event_type == AuditEventType.LOGIN_SUCCESS
        assert log.success is True
        assert log.user_id is None

    @pytest.mark.asyncio
    async def test_log_event_with_user(self, db_session, test_user):
        """Test logging event with user."""
        audit_service = AuditService(db_session)

        log = await audit_service.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user=test_user,
        )

        assert log.user_id == test_user.id

    @pytest.mark.asyncio
    async def test_log_event_with_context(self, db_session, request_context):
        """Test logging event with request context."""
        audit_service = AuditService(db_session)

        log = await audit_service.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            context=request_context,
        )

        assert log.ip_address == request_context.ip_address
        assert log.user_agent == request_context.user_agent
        assert log.request_id == request_context.request_id

    @pytest.mark.asyncio
    async def test_log_event_failed(self, db_session, test_user):
        """Test logging failed event."""
        audit_service = AuditService(db_session)

        log = await audit_service.log_event(
            event_type=AuditEventType.LOGIN_FAILED,
            user=test_user,
            success=False,
            failure_reason="Invalid password",
        )

        assert log.success is False
        assert log.failure_reason == "Invalid password"

    @pytest.mark.asyncio
    async def test_log_event_with_metadata(self, db_session, test_user):
        """Test logging event with metadata."""
        audit_service = AuditService(db_session)

        log = await audit_service.log_event(
            event_type=AuditEventType.OAUTH_LOGIN,
            user=test_user,
            event_data={"provider": "google", "is_new_user": True},
        )

        assert log.event_data == {"provider": "google", "is_new_user": True}

    @pytest.mark.asyncio
    async def test_log_event_with_location(self, db_session, test_user):
        """Test logging event with location."""
        audit_service = AuditService(db_session)

        log = await audit_service.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user=test_user,
            country="United States",
            city="San Francisco",
        )

        assert log.country == "United States"
        assert log.city == "San Francisco"


class TestAuditServiceGetUserLogs:
    """Tests for AuditService.get_user_logs method."""

    @pytest.mark.asyncio
    async def test_get_user_logs_empty(self, db_session, test_user):
        """Test getting logs for user with no logs."""
        audit_service = AuditService(db_session)

        logs, total = await audit_service.get_user_logs(test_user)

        assert logs == []
        assert total == 0

    @pytest.mark.asyncio
    async def test_get_user_logs_with_data(self, db_session, test_user):
        """Test getting logs for user with logs."""
        audit_service = AuditService(db_session)

        # Create some logs
        await audit_service.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user=test_user,
        )
        await audit_service.log_event(
            event_type=AuditEventType.LOGIN_FAILED,
            user=test_user,
            success=False,
        )
        await db_session.flush()

        logs, total = await audit_service.get_user_logs(test_user)

        assert len(logs) == 2
        assert total == 2

    @pytest.mark.asyncio
    async def test_get_user_logs_filter_by_event_type(self, db_session, test_user):
        """Test filtering logs by event type."""
        audit_service = AuditService(db_session)

        await audit_service.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user=test_user,
        )
        await audit_service.log_event(
            event_type=AuditEventType.LOGIN_FAILED,
            user=test_user,
            success=False,
        )
        await db_session.flush()

        logs, total = await audit_service.get_user_logs(
            test_user,
            event_types=[AuditEventType.LOGIN_SUCCESS],
        )

        assert len(logs) == 1
        assert total == 1
        assert logs[0].event_type == AuditEventType.LOGIN_SUCCESS

    @pytest.mark.asyncio
    async def test_get_user_logs_filter_by_success(self, db_session, test_user):
        """Test filtering logs by success status."""
        audit_service = AuditService(db_session)

        await audit_service.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user=test_user,
        )
        await audit_service.log_event(
            event_type=AuditEventType.LOGIN_FAILED,
            user=test_user,
            success=False,
        )
        await db_session.flush()

        logs, total = await audit_service.get_user_logs(
            test_user,
            success_only=True,
        )

        assert len(logs) == 1
        assert logs[0].success is True

    @pytest.mark.asyncio
    async def test_get_user_logs_pagination(self, db_session, test_user):
        """Test pagination of logs."""
        audit_service = AuditService(db_session)

        # Create 5 logs
        for i in range(5):
            await audit_service.log_event(
                event_type=AuditEventType.LOGIN_SUCCESS,
                user=test_user,
            )
        await db_session.flush()

        # Get first page
        logs, total = await audit_service.get_user_logs(
            test_user,
            page=1,
            page_size=2,
        )

        assert len(logs) == 2
        assert total == 5

        # Get second page
        logs, total = await audit_service.get_user_logs(
            test_user,
            page=2,
            page_size=2,
        )

        assert len(logs) == 2
        assert total == 5


class TestAuditServiceFailedLogins:
    """Tests for AuditService.get_recent_failed_logins method."""

    @pytest.mark.asyncio
    async def test_count_failed_logins_none(self, db_session, test_user):
        """Test counting failed logins when none exist."""
        audit_service = AuditService(db_session)

        count = await audit_service.get_recent_failed_logins(user=test_user)

        assert count == 0

    @pytest.mark.asyncio
    async def test_count_failed_logins_by_user(self, db_session, test_user):
        """Test counting failed logins by user."""
        audit_service = AuditService(db_session)

        # Create failed login attempts
        for _ in range(3):
            await audit_service.log_event(
                event_type=AuditEventType.LOGIN_FAILED,
                user=test_user,
                success=False,
            )
        await db_session.flush()

        count = await audit_service.get_recent_failed_logins(user=test_user)

        assert count == 3

    @pytest.mark.asyncio
    async def test_count_failed_logins_by_ip(self, db_session):
        """Test counting failed logins by IP address."""
        audit_service = AuditService(db_session)
        context = RequestContext(
            ip_address="192.168.1.100",
            user_agent="Test",
        )

        # Create failed login attempts
        for _ in range(2):
            await audit_service.log_event(
                event_type=AuditEventType.LOGIN_FAILED,
                context=context,
                success=False,
            )
        await db_session.flush()

        count = await audit_service.get_recent_failed_logins(
            ip_address="192.168.1.100"
        )

        assert count == 2

    @pytest.mark.asyncio
    async def test_count_failed_logins_excludes_old(self, db_session, test_user):
        """Test that old failed logins are excluded."""
        audit_service = AuditService(db_session)

        # Create a recent failed login
        await audit_service.log_event(
            event_type=AuditEventType.LOGIN_FAILED,
            user=test_user,
            success=False,
        )
        await db_session.flush()

        # Count with 30 minute window
        count = await audit_service.get_recent_failed_logins(
            user=test_user,
            minutes=30,
        )

        assert count == 1
