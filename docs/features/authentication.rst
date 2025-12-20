Authentication
==============

Hecate Sentinel supports multiple authentication methods to suit different use cases.

Username/Password Authentication
--------------------------------

Traditional authentication with secure password handling.

**Features:**

- Password hashing with Argon2id (winner of the Password Hashing Competition)
- Secure parameters: ``time_cost=3``, ``memory_cost=64MB``, ``parallelism=4``
- Automatic rehashing when algorithm parameters change
- Login by username or email address

**Endpoints:**

Login
^^^^^

.. code-block:: http

    POST /auth/login
    Content-Type: application/json

    {
        "login": "username_or_email",
        "password": "your_password"
    }

**Response:**

.. code-block:: json

    {
        "access_token": "eyJ...",
        "refresh_token": "eyJ...",
        "token_type": "bearer"
    }

**Error Responses:**

- ``401 Unauthorized``: Invalid credentials
- ``401 Unauthorized``: Account not active
- ``401 Unauthorized``: Email not verified
- ``401 Unauthorized``: Account expired

JWT Tokens
----------

Industry-standard JSON Web Tokens for stateless authentication.

**Token Types:**

.. list-table::
   :widths: 20 20 60
   :header-rows: 1

   * - Type
     - Default TTL
     - Purpose
   * - Access Token
     - 30 minutes
     - Short-lived token for API requests
   * - Refresh Token
     - 7 days
     - Long-lived token to obtain new access tokens

**Token Claims:**

.. list-table::
   :widths: 20 80
   :header-rows: 1

   * - Claim
     - Description
   * - ``iss``
     - Issuer (configurable via ``JWT_ISSUER``)
   * - ``aud``
     - Audience (configurable via ``JWT_AUDIENCE``)
   * - ``sub``
     - Subject (user UUID)
   * - ``iat``
     - Issued at timestamp
   * - ``exp``
     - Expiration timestamp
   * - ``jti``
     - Unique token ID
   * - ``type``
     - Token type (``access`` or ``refresh``)
   * - ``username``
     - User's username
   * - ``is_admin``
     - Admin status flag
   * - ``roles``
     - List of group names
   * - ``permissions``
     - List of permission names
   * - ``token_version``
     - For instant token revocation

Refresh Token
^^^^^^^^^^^^^

.. code-block:: http

    POST /auth/refresh
    Content-Type: application/json

    {
        "refresh_token": "eyJ..."
    }

**Response:**

.. code-block:: json

    {
        "access_token": "eyJ...",
        "refresh_token": "eyJ...",
        "token_type": "bearer"
    }

Logout
^^^^^^

.. code-block:: http

    POST /auth/logout
    Authorization: Bearer <access_token>
    Content-Type: application/json

    {
        "refresh_token": "eyJ..."
    }

Logout All Sessions
^^^^^^^^^^^^^^^^^^^

Invalidates all tokens by incrementing the user's ``token_version``.

.. code-block:: http

    POST /auth/logout-all
    Authorization: Bearer <access_token>

Magic Link Authentication
-------------------------

Passwordless authentication via email.

**Features:**

- Cryptographically secure random tokens
- Configurable expiration (default 15 minutes)
- Single use (tokens invalidated after use)
- Requires verified email address

Request Magic Link
^^^^^^^^^^^^^^^^^^

.. code-block:: http

    POST /auth/magic-link/request
    Content-Type: application/json

    {
        "email": "user@example.com"
    }

**Response:** ``204 No Content`` (always, to prevent email enumeration)

The user receives an email with a link like:
``https://yourapp.com/auth/magic-link?token=abc123...``

Verify Magic Link
^^^^^^^^^^^^^^^^^

.. code-block:: http

    POST /auth/magic-link/verify
    Content-Type: application/json

    {
        "token": "abc123..."
    }

**Response:**

.. code-block:: json

    {
        "access_token": "eyJ...",
        "refresh_token": "eyJ...",
        "token_type": "bearer"
    }

OAuth 2.0 / Social Login
------------------------

Third-party authentication with major providers.

**Supported Providers:**

- Google
- Microsoft (Azure AD / Microsoft 365)

**Features:**

- Automatic account creation for new OAuth users
- Account linking for existing users with matching email
- Token storage for provider API access

Get Available Providers
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

    GET /auth/oauth/providers

**Response:**

.. code-block:: json

    {
        "providers": ["google", "microsoft"]
    }

Start OAuth Flow
^^^^^^^^^^^^^^^^

.. code-block:: http

    GET /auth/oauth/authorize?provider=google

**Response:**

.. code-block:: json

    {
        "authorization_url": "https://accounts.google.com/o/oauth2/..."
    }

Redirect the user to the ``authorization_url``. After authentication, the provider redirects back to your callback URL.

OAuth Callback
^^^^^^^^^^^^^^

.. code-block:: http

    GET /auth/oauth/callback?code=...&state=...

**Response:**

.. code-block:: json

    {
        "access_token": "eyJ...",
        "refresh_token": "eyJ...",
        "token_type": "bearer"
    }

Two-Factor Authentication (TOTP)
--------------------------------

Time-based One-Time Password support for enhanced security.

**Features:**

- Compatible with authenticator apps (Google Authenticator, Authy, etc.)
- QR code generation for easy setup
- 10 single-use recovery codes
- Secrets encrypted at rest

Check TOTP Status
^^^^^^^^^^^^^^^^^

.. code-block:: http

    GET /auth/totp/status
    Authorization: Bearer <access_token>

**Response:**

.. code-block:: json

    {
        "enabled": false,
        "has_recovery_codes": false
    }

Setup TOTP
^^^^^^^^^^

.. code-block:: http

    POST /auth/totp/setup
    Authorization: Bearer <access_token>

**Response:**

.. code-block:: json

    {
        "secret": "JBSWY3DPEHPK3PXP",
        "qr_code": "data:image/png;base64,...",
        "totp_token": "temp_token_for_verification"
    }

Display the QR code for the user to scan with their authenticator app.

Enable TOTP
^^^^^^^^^^^

After scanning the QR code, verify with a code from the authenticator:

.. code-block:: http

    POST /auth/totp/enable
    Authorization: Bearer <access_token>
    Content-Type: application/json

    {
        "code": "123456"
    }

**Response:**

.. code-block:: json

    {
        "message": "TOTP enabled",
        "recovery_codes": [
            "ABCD-1234",
            "EFGH-5678",
            ...
        ]
    }

.. warning::

    Store the recovery codes securely! They are only shown once.

Verify TOTP During Login
^^^^^^^^^^^^^^^^^^^^^^^^

When a user with TOTP enabled logs in, they receive a ``totp_token`` instead of access tokens. They must verify with a TOTP code:

.. code-block:: http

    POST /auth/totp/verify
    Content-Type: application/json

    {
        "totp_token": "...",
        "code": "123456"
    }

Use Recovery Code
^^^^^^^^^^^^^^^^^

If the user loses access to their authenticator:

.. code-block:: http

    POST /auth/totp/recover
    Content-Type: application/json

    {
        "totp_token": "...",
        "code": "ABCD-1234"
    }

Disable TOTP
^^^^^^^^^^^^

.. code-block:: http

    POST /auth/totp/disable
    Authorization: Bearer <access_token>
    Content-Type: application/json

    {
        "password": "current_password",
        "code": "123456"
    }

Regenerate Recovery Codes
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

    POST /auth/totp/recovery-codes
    Authorization: Bearer <access_token>
    Content-Type: application/json

    {
        "password": "current_password"
    }

Password Management
-------------------

Secure password reset and change flows.

Password Reset (Forgot Password)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Request Reset
"""""""""""""

.. code-block:: http

    POST /auth/password/reset/request
    Content-Type: application/json

    {
        "email": "user@example.com"
    }

**Response:** ``204 No Content`` (always, to prevent email enumeration)

Confirm Reset
"""""""""""""

.. code-block:: http

    POST /auth/password/reset/confirm
    Content-Type: application/json

    {
        "token": "reset_token_from_email",
        "new_password": "new_secure_password"
    }

**Features:**

- Email-based reset tokens
- Configurable expiration (default 60 minutes)
- Single use tokens
- Invalidates all existing sessions after reset

Change Password (Authenticated)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

    POST /auth/password/change
    Authorization: Bearer <access_token>
    Content-Type: application/json

    {
        "current_password": "old_password",
        "new_password": "new_password"
    }

**Features:**

- Requires current password verification
- Invalidates all existing sessions after change

Email Verification
------------------

Ensure users own their email addresses.

**Features:**

- Secure, single-use verification tokens
- Configurable expiration (default 24 hours)
- Required for login (configurable)

Verify Email
^^^^^^^^^^^^

.. code-block:: http

    POST /auth/verify-email
    Content-Type: application/json

    {
        "token": "verification_token_from_email"
    }

Resend Verification Email
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

    POST /users/{uuid}/emails/{email_uuid}/resend-verification
    Authorization: Bearer <access_token>
