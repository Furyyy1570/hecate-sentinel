"""Main FastAPI application."""

# Configure logging first, before other imports
from src.core.logging import setup_logging

setup_logging()

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi_reqid import RequestIDMiddleware

from src.api import (
    auth,
    emails,
    groups,
    oauth_accounts,
    permissions,
    phones,
    security,
    sessions,
    users,
)
from src.core.database import check_database_connection, dispose_engine
from src.core.migrations import run_migrations
from src.core.settings import get_settings

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Run migrations on startup (upgrade to head)
    run_migrations()
    await check_database_connection()
    yield
    await dispose_engine()


app = FastAPI(
    title=settings.app_name,
    description="Authentication and Authorization API",
    version="0.1.0",
    debug=settings.debug,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
app.add_middleware(GZipMiddleware, minimum_size=settings.gzip_minimum_size)
app.add_middleware(RequestIDMiddleware, header_name=settings.request_id_header)


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "environment": settings.environment}


# Register routers
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(emails.router)
app.include_router(phones.router)
app.include_router(groups.router)
app.include_router(permissions.router)
app.include_router(oauth_accounts.router)
app.include_router(sessions.router)
app.include_router(security.router)
