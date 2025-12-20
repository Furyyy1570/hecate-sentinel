"""Alembic migration utilities for programmatic execution."""

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, pool

from src.core.settings import get_settings

logger = logging.getLogger(__name__)


def get_alembic_config() -> Config:
    """Get Alembic configuration."""
    # Get the project root directory (where alembic.ini is located)
    project_root = Path(__file__).parent.parent.parent
    alembic_ini = project_root / "alembic.ini"

    if not alembic_ini.exists():
        raise FileNotFoundError(f"alembic.ini not found at {alembic_ini}")

    config = Config(str(alembic_ini))

    # Override the sqlalchemy.url with our settings using sync driver
    settings = get_settings()
    sync_url = settings.database_url.replace(
        "postgresql+asyncpg://", "postgresql+psycopg2://"
    )
    config.set_main_option("sqlalchemy.url", sync_url)

    return config


def run_migrations() -> None:
    """Run all pending migrations (upgrade to head).

    This function uses synchronous SQLAlchemy to run migrations,
    which is safe to call from both sync and async contexts.
    """
    logger.info("Running database migrations...")

    settings = get_settings()
    sync_url = settings.database_url.replace(
        "postgresql+asyncpg://", "postgresql+psycopg2://"
    )

    # Create sync engine for migrations
    engine = create_engine(sync_url, poolclass=pool.NullPool)

    # Use alembic programmatically with our sync engine
    from alembic.runtime.migration import MigrationContext
    from alembic.operations import Operations
    from alembic.script import ScriptDirectory

    config = get_alembic_config()
    script = ScriptDirectory.from_config(config)

    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        current_rev = context.get_current_revision()
        head_rev = script.get_current_head()

        if current_rev == head_rev:
            logger.info(f"Database is up to date at revision {current_rev}")
        else:
            logger.info(f"Upgrading from {current_rev} to {head_rev}")
            # Run upgrade using alembic command
            command.upgrade(config, "head")
            logger.info("Database migrations completed.")

    engine.dispose()


def get_current_revision() -> str | None:
    """Get the current database revision."""
    from alembic.runtime.migration import MigrationContext

    settings = get_settings()
    sync_url = settings.database_url.replace(
        "postgresql+asyncpg://", "postgresql+psycopg2://"
    )
    engine = create_engine(sync_url, poolclass=pool.NullPool)

    with engine.connect() as conn:
        context = MigrationContext.configure(conn)
        revision = context.get_current_revision()

    engine.dispose()
    return revision
