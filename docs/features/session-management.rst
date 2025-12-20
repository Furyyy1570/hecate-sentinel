Session Management
==================

Hecate Sentinel tracks active user sessions with detailed device and location information.

Session Tracking
----------------

Every login creates a tracked session with:

- Refresh token hash (for identification)
- Device fingerprint (from User-Agent parsing)
- Geolocation data (from IP address)
- Activity timestamps

Session Information
^^^^^^^^^^^^^^^^^^^

Each session stores:

**Device Information:**

- Device type (mobile, tablet, desktop, bot)
- Browser and version
- Operating system and version
- Device brand and model

**Location Information:**

- Country and country code
- Region and city
- Latitude and longitude
- Timezone
- ISP

**Timestamps:**

- Creation time
- Last activity time
- Expiration time
- Revocation time (if revoked)

Active Sessions API
-------------------

List Active Sessions
^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

    GET /sessions
    Authorization: Bearer <access_token>

**Response:**

.. code-block:: json

    {
        "sessions": [
            {
                "uuid": "session-uuid",
                "device_type": "desktop",
                "browser": "Chrome",
                "os": "Windows",
                "device_brand": null,
                "device_model": null,
                "country": "United States",
                "city": "San Francisco",
                "ip_address": "203.0.113.42",
                "created_at": "2025-01-15T10:00:00Z",
                "last_activity_at": "2025-01-15T14:30:00Z",
                "is_current": true
            },
            {
                "uuid": "session-uuid-2",
                "device_type": "mobile",
                "browser": "Safari",
                "os": "iOS",
                "device_brand": "Apple",
                "device_model": "iPhone",
                "country": "United States",
                "city": "New York",
                "ip_address": "203.0.113.100",
                "created_at": "2025-01-10T08:00:00Z",
                "last_activity_at": "2025-01-14T20:15:00Z",
                "is_current": false
            }
        ],
        "total": 2
    }

The ``is_current`` flag indicates the session making the current request.

Revoke Specific Session
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

    DELETE /sessions/{uuid}
    Authorization: Bearer <access_token>

**Response:**

.. code-block:: json

    {
        "message": "Session revoked successfully"
    }

This immediately invalidates the session's refresh token.

Revoke All Sessions
^^^^^^^^^^^^^^^^^^^

.. code-block:: http

    DELETE /sessions
    Authorization: Bearer <access_token>

**Query Parameters:**

- ``keep_current`` (bool): Keep the current session active (default: true)

**Response:**

.. code-block:: json

    {
        "message": "5 sessions revoked"
    }

Logout All Sessions (Token Invalidation)
----------------------------------------

For immediate invalidation of all tokens (including access tokens that haven't expired yet):

.. code-block:: http

    POST /auth/logout-all
    Authorization: Bearer <access_token>

This increments the user's ``token_version``, which invalidates all previously issued tokens.

Session Lifecycle
-----------------

Creation
^^^^^^^^

Sessions are created during:

- Username/password login
- Magic link verification
- OAuth callback
- TOTP verification

Validation
^^^^^^^^^^

Sessions are validated on each refresh token use:

1. Token signature verification
2. Token expiration check
3. Session lookup in database
4. User status verification (active, not expired, not deleted)
5. Token version comparison

Activity Tracking
^^^^^^^^^^^^^^^^^

The ``last_activity_at`` timestamp is updated when:

- The refresh token is used to obtain new access tokens
- The user makes authenticated API requests

Revocation
^^^^^^^^^^

Sessions can be revoked:

- Manually via the API
- On password change
- On password reset
- On "logout all" action

Expired sessions are automatically cleaned up.

Implementation Details
----------------------

Token Hashing
^^^^^^^^^^^^^

Refresh tokens are hashed with SHA-256 for storage. The full token is never stored in the database.

.. code-block:: python

    import hashlib

    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

Device Fingerprinting
^^^^^^^^^^^^^^^^^^^^^

Device information is extracted from the ``User-Agent`` header using the ``user-agents`` library.

.. code-block:: python

    from user_agents import parse

    ua = parse(user_agent_string)
    device_type = "mobile" if ua.is_mobile else "desktop"
    browser = ua.browser.family
    os = ua.os.family

Geolocation
^^^^^^^^^^^

IP geolocation uses the free ``ip-api.com`` service:

- Rate limit: 45 requests per minute
- Private IPs (localhost, internal networks) are skipped
- Failed lookups don't block authentication

.. note::

    For production deployments with high traffic, consider using a local MaxMind GeoIP database or a paid geolocation service with higher rate limits.
