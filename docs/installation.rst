Installation
============

This guide covers the different ways to install and run Hecate Sentinel.

Prerequisites
-------------

- Python 3.14 or higher
- PostgreSQL 15 or higher
- Docker and Docker Compose (for containerized deployment)

Quick Start with Docker
-----------------------

The fastest way to get Hecate Sentinel running is with Docker Compose.

1. Clone the repository:

   .. code-block:: bash

       git clone https://github.com/your-org/hecate-sentinel.git
       cd hecate-sentinel

2. Create a ``.env`` file with your configuration:

   .. code-block:: bash

       cp .env.example .env

3. **Important**: Set a secure ``SECRET_KEY``:

   .. code-block:: bash

       # Generate a secure secret key
       python -c "import secrets; print(secrets.token_urlsafe(32))"

   Add this to your ``.env`` file:

   .. code-block:: text

       SECRET_KEY=your-generated-secret-key

4. Start the services:

   .. code-block:: bash

       docker compose up -d

5. The API is now available at http://localhost:8000

   - OpenAPI docs: http://localhost:8000/docs
   - Health check: http://localhost:8000/health

Default Admin User
^^^^^^^^^^^^^^^^^^

On first startup, the migration automatically creates an admin user:

- **Username**: ``admin``
- **Email**: ``admin@example.com``
- **Password**: ``admin1234qwer``
- **Group**: ``site_admins``

.. warning::

   Change these credentials immediately in production!

Development Installation
------------------------

For local development without Docker:

1. Install `uv <https://docs.astral.sh/uv/>`_ (recommended) or pip:

   .. code-block:: bash

       # Install uv
       curl -LsSf https://astral.sh/uv/install.sh | sh

2. Clone and install dependencies:

   .. code-block:: bash

       git clone https://github.com/your-org/hecate-sentinel.git
       cd hecate-sentinel
       uv sync

3. Start PostgreSQL (using Docker or local installation):

   .. code-block:: bash

       # Using Docker
       docker run -d \
         --name hecate-postgres \
         -e POSTGRES_USER=hecate \
         -e POSTGRES_PASSWORD=hecate \
         -e POSTGRES_DB=hecate_sentinel \
         -p 5432:5432 \
         postgres:18-alpine

4. Create a ``.env`` file:

   .. code-block:: text

       SECRET_KEY=dev-secret-key-change-in-production
       DB_HOST=localhost
       DB_PORT=5432
       DB_USER=hecate
       DB_PASSWORD=hecate
       DB_NAME=hecate_sentinel
       DEBUG=true
       ENVIRONMENT=development

5. Run the application:

   .. code-block:: bash

       uv run uvicorn src.main:app --reload

   The API is now available at http://localhost:8000

Running Tests
-------------

Tests require a PostgreSQL database. The test suite creates a separate ``hecate_sentinel_test`` database.

1. Start PostgreSQL (if not already running):

   .. code-block:: bash

       docker compose up -d db

2. Run the tests:

   .. code-block:: bash

       # Run all tests
       uv run pytest

       # Run with coverage
       uv run pytest --cov=src --cov-report=html

       # Run specific test file
       uv run pytest tests/services/test_auth.py

Building the Docker Image
-------------------------

To build the Docker image manually:

.. code-block:: bash

    docker build -t hecate-sentinel .

The Dockerfile uses a single-stage build optimized for production:

.. code-block:: dockerfile

    FROM python:3.14-slim
    # ... installs uv and dependencies
    CMD ["uv", "run", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]

Verifying Installation
----------------------

After starting the service, verify it's working:

.. code-block:: bash

    # Check health endpoint
    curl http://localhost:8000/health

    # Expected response
    {"status": "healthy", "environment": "production"}

    # Login with default admin
    curl -X POST http://localhost:8000/auth/login \
      -H "Content-Type: application/json" \
      -d '{"login": "admin", "password": "admin1234qwer"}'
