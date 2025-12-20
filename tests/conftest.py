"""Pytest configuration and fixtures for Hecate Sentinel tests."""

import asyncio
import os
from collections.abc import AsyncGenerator, Generator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from fastapi import Request
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from src.core.database import Base, get_session
from src.core.request_context import RequestContext
from src.main import app
from src.models.user import User


# Use PostgreSQL test database (same container, different database)
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://hecate:hecate@localhost:5432/hecate_sentinel_test",
)


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def engine():
    """Create a test database engine."""
    # Create the test database if it doesn't exist
    from sqlalchemy import create_engine, text
    from sqlalchemy.exc import ProgrammingError

    sync_url = TEST_DATABASE_URL.replace("postgresql+asyncpg://", "postgresql+psycopg2://")
    base_url = sync_url.rsplit("/", 1)[0] + "/postgres"

    sync_engine = create_engine(base_url, isolation_level="AUTOCOMMIT")
    try:
        with sync_engine.connect() as conn:
            conn.execute(text("CREATE DATABASE hecate_sentinel_test"))
    except ProgrammingError:
        pass  # Database already exists
    finally:
        sync_engine.dispose()

    engine = create_async_engine(
        TEST_DATABASE_URL,
        poolclass=NullPool,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    async_session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session_factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create a test client with database session override."""

    async def override_get_session() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_session] = override_get_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://localhost") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture
def mock_request() -> MagicMock:
    """Create a mock FastAPI request."""
    request = MagicMock(spec=Request)
    request.client.host = "127.0.0.1"
    request.headers = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "x-request-id": "test-request-id",
    }
    return request


@pytest.fixture
def request_context() -> RequestContext:
    """Create a test request context."""
    return RequestContext(
        ip_address="127.0.0.1",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        request_id="test-request-id",
    )


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    """Create a test user."""
    from src.core.security import hash_password

    user = User(
        username="testuser",
        password=hash_password("testpassword123"),
        is_admin=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def test_admin_user(db_session: AsyncSession) -> User:
    """Create a test admin user."""
    from src.core.security import hash_password

    user = User(
        username="adminuser",
        password=hash_password("adminpassword123"),
        is_admin=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def verified_user(db_session: AsyncSession, test_user: User) -> User:
    """Create a test user with verified email."""
    from src.models.email import Email

    email = Email(
        user_id=test_user.id,
        email_address="test@example.com",
        is_primary=True,
        is_verified=True,
    )
    db_session.add(email)
    await db_session.commit()
    return test_user


@pytest.fixture
def mock_email_sender() -> AsyncMock:
    """Create a mock email sender."""
    sender = AsyncMock()
    sender.send_email.return_value = True
    sender.send_verification_email.return_value = True
    sender.send_password_reset_email.return_value = True
    sender.send_magic_link_email.return_value = True
    sender.send_new_device_alert.return_value = True
    sender.send_new_location_alert.return_value = True
    return sender


@pytest.fixture
def mock_geoip() -> AsyncMock:
    """Create a mock geoip service."""
    from src.core.geoip import GeoLocation

    mock = AsyncMock()
    mock.return_value = GeoLocation(
        country="United States",
        country_code="US",
        region="California",
        city="San Francisco",
        latitude=37.7749,
        longitude=-122.4194,
        timezone="America/Los_Angeles",
        isp="Test ISP",
    )
    return mock
