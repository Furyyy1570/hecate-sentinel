API Guide
=========

This guide covers general API usage patterns for Hecate Sentinel.

Base URL
--------

All API endpoints are relative to your Hecate Sentinel instance:

.. code-block:: text

    http://localhost:8000   # Development
    https://api.example.com # Production

OpenAPI Documentation
---------------------

Interactive API documentation is available at:

- **Swagger UI**: ``/docs``
- **ReDoc**: ``/redoc``
- **OpenAPI JSON**: ``/openapi.json``

Authentication
--------------

Most endpoints require authentication via Bearer token.

.. code-block:: http

    GET /users
    Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

Obtaining Tokens
^^^^^^^^^^^^^^^^

1. **Login with credentials:**

   .. code-block:: bash

       curl -X POST http://localhost:8000/auth/login \
         -H "Content-Type: application/json" \
         -d '{"login": "username", "password": "password"}'

2. **Store the tokens:**

   .. code-block:: json

       {
           "access_token": "eyJ...",
           "refresh_token": "eyJ...",
           "token_type": "bearer"
       }

3. **Use the access token for API requests**

Refreshing Tokens
^^^^^^^^^^^^^^^^^

Before the access token expires, use the refresh token to get new tokens:

.. code-block:: bash

    curl -X POST http://localhost:8000/auth/refresh \
      -H "Content-Type: application/json" \
      -d '{"refresh_token": "eyJ..."}'

Request Format
--------------

Content Type
^^^^^^^^^^^^

All request bodies should use JSON:

.. code-block:: http

    POST /users
    Content-Type: application/json

    {"username": "newuser", "password": "password123"}

Query Parameters
^^^^^^^^^^^^^^^^

Use query parameters for filtering and pagination:

.. code-block:: http

    GET /users?page=1&page_size=20
    GET /security/audit-log?event_types=login_success&event_types=login_failed

Response Format
---------------

Successful Responses
^^^^^^^^^^^^^^^^^^^^

**Single Resource (200 OK):**

.. code-block:: json

    {
        "uuid": "abc-123",
        "username": "johndoe",
        "is_admin": false
    }

**Collection (200 OK):**

.. code-block:: json

    {
        "items": [
            {"uuid": "abc-123", "username": "johndoe"},
            {"uuid": "def-456", "username": "janedoe"}
        ],
        "total": 100,
        "page": 1,
        "page_size": 50
    }

**Created (201 Created):**

.. code-block:: json

    {
        "uuid": "new-uuid",
        "username": "newuser"
    }

**No Content (204 No Content):**

Empty response body.

**Message Response:**

.. code-block:: json

    {
        "message": "Operation completed successfully"
    }

Error Responses
^^^^^^^^^^^^^^^

All errors follow a consistent format:

.. code-block:: json

    {
        "detail": "Error message describing what went wrong"
    }

**Common HTTP Status Codes:**

.. list-table::
   :widths: 15 85
   :header-rows: 1

   * - Code
     - Description
   * - 400
     - Bad Request - Invalid input data
   * - 401
     - Unauthorized - Missing or invalid authentication
   * - 403
     - Forbidden - Insufficient permissions
   * - 404
     - Not Found - Resource doesn't exist
   * - 409
     - Conflict - Resource already exists (e.g., duplicate username)
   * - 422
     - Unprocessable Entity - Validation error
   * - 500
     - Internal Server Error - Server-side error

Validation Errors
^^^^^^^^^^^^^^^^^

Pydantic validation errors include field-level details:

.. code-block:: json

    {
        "detail": [
            {
                "loc": ["body", "username"],
                "msg": "String should have at least 3 characters",
                "type": "string_too_short"
            }
        ]
    }

Pagination
----------

List endpoints support pagination:

.. code-block:: http

    GET /users?page=2&page_size=25

**Parameters:**

- ``page`` (int): Page number, starting from 1 (default: 1)
- ``page_size`` (int): Items per page (default: 50, max: 100)

**Response:**

.. code-block:: json

    {
        "items": [...],
        "total": 250,
        "page": 2,
        "page_size": 25
    }

Request ID Tracking
-------------------

Every request is assigned a unique ID for tracing:

.. code-block:: http

    GET /health
    X-Request-ID: req-abc-123

If you don't provide a request ID, one is generated automatically. The request ID is included in logs and can be used for debugging.

Rate Limiting
-------------

Currently, Hecate Sentinel doesn't implement rate limiting at the application level. Consider implementing rate limiting at your reverse proxy (nginx, Traefik) or API gateway.

CORS
----

Cross-Origin Resource Sharing is configured via environment variables:

.. code-block:: text

    CORS_ORIGINS=["https://app.example.com"]
    CORS_ALLOW_CREDENTIALS=true

Ensure your frontend domain is included in ``CORS_ORIGINS``.

Health Check
------------

Use the health endpoint for monitoring:

.. code-block:: bash

    curl http://localhost:8000/health

**Response:**

.. code-block:: json

    {
        "status": "healthy",
        "environment": "production"
    }

API Endpoints Summary
---------------------

Authentication
^^^^^^^^^^^^^^

.. list-table::
   :widths: 15 40 45
   :header-rows: 1

   * - Method
     - Endpoint
     - Description
   * - POST
     - ``/auth/login``
     - Login with username/password
   * - POST
     - ``/auth/refresh``
     - Refresh access token
   * - POST
     - ``/auth/logout``
     - Logout (invalidate refresh token)
   * - POST
     - ``/auth/logout-all``
     - Logout all sessions
   * - POST
     - ``/auth/magic-link/request``
     - Request magic link
   * - POST
     - ``/auth/magic-link/verify``
     - Verify magic link
   * - GET
     - ``/auth/oauth/providers``
     - List OAuth providers
   * - GET
     - ``/auth/oauth/authorize``
     - Start OAuth flow
   * - GET
     - ``/auth/oauth/callback``
     - OAuth callback
   * - GET
     - ``/auth/totp/status``
     - Check TOTP status
   * - POST
     - ``/auth/totp/setup``
     - Setup TOTP
   * - POST
     - ``/auth/totp/enable``
     - Enable TOTP
   * - POST
     - ``/auth/totp/disable``
     - Disable TOTP
   * - POST
     - ``/auth/totp/verify``
     - Verify TOTP code
   * - POST
     - ``/auth/totp/recover``
     - Use recovery code
   * - POST
     - ``/auth/password/reset/request``
     - Request password reset
   * - POST
     - ``/auth/password/reset/confirm``
     - Confirm password reset
   * - POST
     - ``/auth/password/change``
     - Change password
   * - POST
     - ``/auth/verify-email``
     - Verify email address

Users
^^^^^

.. list-table::
   :widths: 15 40 45
   :header-rows: 1

   * - Method
     - Endpoint
     - Description
   * - GET
     - ``/users``
     - List users
   * - POST
     - ``/users``
     - Create user
   * - GET
     - ``/users/{uuid}``
     - Get user
   * - PUT
     - ``/users/{uuid}``
     - Update user
   * - DELETE
     - ``/users/{uuid}``
     - Delete user

Sessions
^^^^^^^^

.. list-table::
   :widths: 15 40 45
   :header-rows: 1

   * - Method
     - Endpoint
     - Description
   * - GET
     - ``/sessions``
     - List active sessions
   * - DELETE
     - ``/sessions/{uuid}``
     - Revoke session
   * - DELETE
     - ``/sessions``
     - Revoke all sessions

Security
^^^^^^^^

.. list-table::
   :widths: 15 40 45
   :header-rows: 1

   * - Method
     - Endpoint
     - Description
   * - GET
     - ``/security/audit-log``
     - Get audit log
   * - GET
     - ``/security/devices``
     - List known devices
   * - GET
     - ``/security/locations``
     - List known locations

Groups & Permissions
^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :widths: 15 40 45
   :header-rows: 1

   * - Method
     - Endpoint
     - Description
   * - GET
     - ``/groups``
     - List groups
   * - POST
     - ``/groups``
     - Create group
   * - GET
     - ``/groups/{uuid}``
     - Get group
   * - PUT
     - ``/groups/{uuid}``
     - Update group
   * - DELETE
     - ``/groups/{uuid}``
     - Delete group
   * - GET
     - ``/permissions``
     - List permissions
   * - POST
     - ``/permissions``
     - Create permission
   * - GET
     - ``/permissions/{uuid}``
     - Get permission
   * - PUT
     - ``/permissions/{uuid}``
     - Update permission
   * - DELETE
     - ``/permissions/{uuid}``
     - Delete permission
