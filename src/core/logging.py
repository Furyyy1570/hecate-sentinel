"""Centralized logging configuration for Docker-friendly console output."""

import logging
import sys

from src.core.settings import get_settings


def setup_logging() -> None:
    """Configure logging for the application.

    All logs go to stderr for Docker container compatibility.
    Log level can be set via LOG_LEVEL env var (DEBUG, INFO, WARNING, ERROR).
    Defaults to DEBUG when debug=True, otherwise uses LOG_LEVEL setting.
    """
    settings = get_settings()

    # Debug mode overrides to DEBUG, otherwise use configured level
    if settings.debug:
        log_level = logging.DEBUG
    else:
        log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)-8s [%(name)s] %(filename)s:%(lineno)d - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
        force=True,  # Override any existing configuration
    )

    # Set specific log levels for noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    # SQLAlchemy logging - only show SQL in debug mode
    if settings.debug:
        logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO)
    else:
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    # Alembic logging
    logging.getLogger("alembic").setLevel(logging.INFO)

    logging.info(
        f"Logging configured: level={logging.getLevelName(log_level)}, "
        f"environment={settings.environment}"
    )
