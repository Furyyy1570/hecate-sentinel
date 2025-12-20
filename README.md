# Hecate Sentinel

Authentication and Authorization API built with FastAPI.

## Prerequisites

- Python 3.14+
- PostgreSQL 18+
- [uv](https://docs.astral.sh/uv/)

Or alternatively:
- Docker and Docker Compose

## Setup

1. Install dependencies:
```bash
uv sync
```

2. Set up PostgreSQL database and configure environment variables:
```bash
cp .env.example .env
# Edit .env with your database credentials
```

## Docker

The easiest way to run the service is with Docker Compose.

### Quick Start

1. Copy and configure environment variables:
```bash
cp .env.example .env
# Edit .env - at minimum set SECRET_KEY
```

2. Start the services:
```bash
docker compose up -d
```

### Commands

View logs:
```bash
docker compose logs -f api
```

Stop services:
```bash
docker compose down
```

Stop and remove volumes (reset database):
```bash
docker compose down -v
```

Rebuild after code changes:
```bash
docker compose build && docker compose up -d
```

### Access Points

| Service | URL |
|---------|-----|
| API | http://localhost:8000 |
| Swagger Docs | http://localhost:8000/docs |
| ReDoc | http://localhost:8000/redoc |
| PostgreSQL | localhost:5433 |

## Running the Service (without Docker)

Start the development server:
```bash
uv run uvicorn src.main:app --reload
```

With custom host and port:
```bash
uv run uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

**Note:** Migrations are automatically applied on startup (upgrade to head).

## Database Migrations

Migrations are managed with Alembic.

### Create a New Migration

Auto-generate migration from model changes:
```bash
uv run alembic revision --autogenerate -m "description of changes"
```

Create an empty migration:
```bash
uv run alembic revision -m "description of changes"
```

### Apply Migrations

Upgrade to the latest version (head):
```bash
uv run alembic upgrade head
```

Upgrade by one revision:
```bash
uv run alembic upgrade +1
```

Apply a specific migration by revision ID:
```bash
uv run alembic upgrade <revision_id>
```

### Downgrade Migrations

Downgrade by one revision:
```bash
uv run alembic downgrade -1
```

Downgrade to a specific revision:
```bash
uv run alembic downgrade <revision_id>
```

Downgrade to base (remove all migrations):
```bash
uv run alembic downgrade base
```

### View Migration Status

Show current revision:
```bash
uv run alembic current
```

Show migration history:
```bash
uv run alembic history
```

Show pending migrations:
```bash
uv run alembic history --indicate-current
```

## Running Tests

Tests require a PostgreSQL test database. By default, tests use:
```
postgresql+asyncpg://hecate:hecate@localhost:5432/hecate_sentinel_test
```

Override with the `TEST_DATABASE_URL` environment variable if needed.

### Run All Tests

```bash
uv run pytest
```

With verbose output:
```bash
uv run pytest -v
```

### Run Specific Test Categories

Core utility tests:
```bash
uv run pytest tests/core/ -v
```

Service tests:
```bash
uv run pytest tests/services/ -v
```

API endpoint tests:
```bash
uv run pytest tests/api/ -v
```

### Run a Specific Test File

```bash
uv run pytest tests/api/test_auth.py -v
```

### Run a Specific Test

```bash
uv run pytest tests/api/test_auth.py::TestAuthLogin::test_login_success -v
```

### Run Tests with Coverage

```bash
uv run pytest --cov=src --cov-report=term-missing
```

Generate HTML coverage report:
```bash
uv run pytest --cov=src --cov-report=html
```

### Run Tests in Parallel

```bash
uv run pytest -n auto
```

## Project Structure

```
hecate-sentinel/
├── alembic/              # Database migrations
│   ├── versions/         # Migration scripts
│   └── env.py            # Alembic configuration
├── src/
│   ├── api/              # API route handlers
│   ├── core/             # Core utilities (security, geoip, etc.)
│   ├── models/           # SQLAlchemy models
│   ├── schemas/          # Pydantic schemas
│   ├── services/         # Business logic services
│   └── main.py           # Application entry point
├── tests/
│   ├── api/              # API endpoint tests
│   ├── core/             # Core utility tests
│   ├── services/         # Service tests
│   └── conftest.py       # Test fixtures
├── alembic.ini           # Alembic settings
├── compose.yaml          # Docker Compose configuration
├── Dockerfile            # Container build instructions
├── pyproject.toml        # Project dependencies
└── pytest.ini            # Pytest configuration
```
