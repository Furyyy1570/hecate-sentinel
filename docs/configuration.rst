Configuration
=============

Hecate Sentinel is configured via environment variables, following the `12-factor app <https://12factor.net/config>`_ methodology. All settings can be provided via environment variables or a ``.env`` file.

Environment Variables
---------------------

Application Settings
^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :widths: 30 15 55
   :header-rows: 1

   * - Variable
     - Default
     - Description
   * - ``APP_NAME``
     - ``Hecate Sentinel``
     - Application name displayed in logs and emails
   * - ``DEBUG``
     - ``false``
     - Enable debug mode (additional logging, detailed errors)
   * - ``ENVIRONMENT``
     - ``development``
     - Environment name (``development``, ``staging``, ``production``)
   * - ``LOG_LEVEL``
     - ``INFO``
     - Logging level (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``)
   * - ``HOST``
     - ``0.0.0.0``
     - Host to bind the server to
   * - ``PORT``
     - ``8000``
     - Port to bind the server to

Database Settings
^^^^^^^^^^^^^^^^^

.. list-table::
   :widths: 30 15 55
   :header-rows: 1

   * - Variable
     - Default
     - Description
   * - ``DB_HOST``
     - ``localhost``
     - PostgreSQL host
   * - ``DB_PORT``
     - ``5432``
     - PostgreSQL port
   * - ``DB_USER``
     - ``hecate``
     - Database username
   * - ``DB_PASSWORD``
     - ``hecate``
     - Database password
   * - ``DB_NAME``
     - ``hecate_sentinel``
     - Database name
   * - ``DB_POOL_SIZE``
     - ``5``
     - Connection pool size
   * - ``DB_MAX_OVERFLOW``
     - ``10``
     - Maximum overflow connections

Security Settings
^^^^^^^^^^^^^^^^^

.. list-table::
   :widths: 30 15 55
   :header-rows: 1

   * - Variable
     - Default
     - Description
   * - ``SECRET_KEY``
     - ``change-me-in-production``
     - **Required in production**. Secret key for JWT signing. Generate with: ``python -c "import secrets; print(secrets.token_urlsafe(32))"``
   * - ``JWT_ALGORITHM``
     - ``HS256``
     - JWT signing algorithm
   * - ``JWT_ISSUER``
     - ``hecate-sentinel``
     - JWT issuer claim
   * - ``JWT_AUDIENCE``
     - ``hecate-sentinel-api``
     - JWT audience claim
   * - ``ACCESS_TOKEN_EXPIRE_MINUTES``
     - ``30``
     - Access token expiration time in minutes

Authentication Settings
^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :widths: 30 15 55
   :header-rows: 1

   * - Variable
     - Default
     - Description
   * - ``ALLOW_REGISTRATION``
     - ``false``
     - Allow public user registration
   * - ``REFRESH_TOKEN_EXPIRE_DAYS``
     - ``7``
     - Refresh token expiration time in days
   * - ``MAGIC_LINK_EXPIRE_MINUTES``
     - ``15``
     - Magic link expiration time in minutes
   * - ``PASSWORD_RESET_EXPIRE_MINUTES``
     - ``60``
     - Password reset token expiration in minutes
   * - ``EMAIL_VERIFICATION_EXPIRE_HOURS``
     - ``24``
     - Email verification token expiration in hours

SMTP Settings
^^^^^^^^^^^^^

.. list-table::
   :widths: 30 15 55
   :header-rows: 1

   * - Variable
     - Default
     - Description
   * - ``SMTP_HOST``
     - ``localhost``
     - SMTP server hostname
   * - ``SMTP_PORT``
     - ``587``
     - SMTP server port
   * - ``SMTP_USERNAME``
     - (none)
     - SMTP authentication username
   * - ``SMTP_PASSWORD``
     - (none)
     - SMTP authentication password
   * - ``SMTP_USE_TLS``
     - ``true``
     - Use TLS for SMTP connection
   * - ``SMTP_FROM_EMAIL``
     - ``noreply@example.com``
     - Sender email address
   * - ``SMTP_FROM_NAME``
     - ``Hecate Sentinel``
     - Sender display name

CORS Settings
^^^^^^^^^^^^^

.. list-table::
   :widths: 30 15 55
   :header-rows: 1

   * - Variable
     - Default
     - Description
   * - ``CORS_ORIGINS``
     - ``["http://localhost:3000"]``
     - Allowed origins (JSON array)
   * - ``CORS_ALLOW_CREDENTIALS``
     - ``true``
     - Allow credentials in CORS requests
   * - ``CORS_ALLOW_METHODS``
     - ``["*"]``
     - Allowed HTTP methods
   * - ``CORS_ALLOW_HEADERS``
     - ``["*"]``
     - Allowed HTTP headers

OAuth Settings
^^^^^^^^^^^^^^

**Google OAuth**

.. list-table::
   :widths: 30 15 55
   :header-rows: 1

   * - Variable
     - Default
     - Description
   * - ``GOOGLE_CLIENT_ID``
     - (none)
     - Google OAuth client ID
   * - ``GOOGLE_CLIENT_SECRET``
     - (none)
     - Google OAuth client secret

**Microsoft OAuth**

.. list-table::
   :widths: 30 15 55
   :header-rows: 1

   * - Variable
     - Default
     - Description
   * - ``MICROSOFT_CLIENT_ID``
     - (none)
     - Microsoft OAuth client ID
   * - ``MICROSOFT_CLIENT_SECRET``
     - (none)
     - Microsoft OAuth client secret
   * - ``MICROSOFT_TENANT_ID``
     - ``common``
     - Microsoft tenant ID (``common`` for multi-tenant)

**OAuth General**

.. list-table::
   :widths: 30 15 55
   :header-rows: 1

   * - Variable
     - Default
     - Description
   * - ``OAUTH_REDIRECT_URI``
     - ``http://localhost:8000/auth/oauth/callback``
     - OAuth callback URL
   * - ``OAUTH_STATE_EXPIRE_MINUTES``
     - ``10``
     - OAuth state token expiration

Other Settings
^^^^^^^^^^^^^^

.. list-table::
   :widths: 30 15 55
   :header-rows: 1

   * - Variable
     - Default
     - Description
   * - ``TRUSTED_HOSTS``
     - ``["localhost", "127.0.0.1"]``
     - Trusted host headers (JSON array)
   * - ``GZIP_MINIMUM_SIZE``
     - ``1000``
     - Minimum response size for GZip compression
   * - ``REQUEST_ID_HEADER``
     - ``X-Request-ID``
     - Header name for request ID tracking
   * - ``FRONTEND_URL``
     - ``http://localhost:3000``
     - Frontend application URL (used in email links)

Example Configuration Files
---------------------------

Development (.env)
^^^^^^^^^^^^^^^^^^

.. code-block:: text

    # Application
    DEBUG=true
    ENVIRONMENT=development
    LOG_LEVEL=DEBUG

    # Database
    DB_HOST=localhost
    DB_PORT=5432
    DB_USER=hecate
    DB_PASSWORD=hecate
    DB_NAME=hecate_sentinel

    # Security
    SECRET_KEY=dev-secret-key-not-for-production

    # Authentication
    ALLOW_REGISTRATION=true

    # Frontend
    FRONTEND_URL=http://localhost:3000
    CORS_ORIGINS=["http://localhost:3000", "http://localhost:5173"]

Production (.env)
^^^^^^^^^^^^^^^^^

.. code-block:: text

    # Application
    DEBUG=false
    ENVIRONMENT=production
    LOG_LEVEL=INFO

    # Database
    DB_HOST=db.internal
    DB_PORT=5432
    DB_USER=hecate_prod
    DB_PASSWORD=${DB_PASSWORD}
    DB_NAME=hecate_sentinel
    DB_POOL_SIZE=10
    DB_MAX_OVERFLOW=20

    # Security (use a strong, unique secret!)
    SECRET_KEY=${SECRET_KEY}
    ACCESS_TOKEN_EXPIRE_MINUTES=15

    # Authentication
    ALLOW_REGISTRATION=false
    REFRESH_TOKEN_EXPIRE_DAYS=30

    # SMTP
    SMTP_HOST=smtp.sendgrid.net
    SMTP_PORT=587
    SMTP_USERNAME=apikey
    SMTP_PASSWORD=${SENDGRID_API_KEY}
    SMTP_FROM_EMAIL=auth@yourdomain.com
    SMTP_FROM_NAME=Your App

    # Frontend
    FRONTEND_URL=https://app.yourdomain.com
    CORS_ORIGINS=["https://app.yourdomain.com"]

    # Trusted hosts
    TRUSTED_HOSTS=["app.yourdomain.com", "api.yourdomain.com"]

    # OAuth (optional)
    GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
    GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}
    OAUTH_REDIRECT_URI=https://api.yourdomain.com/auth/oauth/callback

Configuration Validation
------------------------

Hecate Sentinel validates all configuration at startup using Pydantic. If required settings are missing or invalid, the application will fail to start with a clear error message.

.. code-block:: text

    pydantic_core._pydantic_core.ValidationError: 1 validation error for Settings
    SECRET_KEY
      Field required [type=missing, input_value={}, input_type=dict]

Security Recommendations
------------------------

1. **SECRET_KEY**: Use a cryptographically secure random string of at least 32 characters. Never commit this to version control.

2. **Database Password**: Use a strong, unique password. Consider using a secrets manager.

3. **CORS Origins**: In production, specify exact allowed origins. Never use ``["*"]``.

4. **Debug Mode**: Always set ``DEBUG=false`` in production.

5. **HTTPS**: Always use HTTPS in production. Configure your reverse proxy (nginx, Traefik) to handle TLS.
