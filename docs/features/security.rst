Security Features
=================

Hecate Sentinel includes comprehensive security monitoring and protection features.

New Device Detection
--------------------

Alerts users when they log in from an unrecognized device.

**How it works:**

1. On each login, the device fingerprint is computed from the User-Agent
2. The fingerprint is compared against the user's known devices
3. If new, an email alert is sent and the device is recorded
4. The login proceeds normally (device detection doesn't block access)

**Device Fingerprint:**

A normalized hash of:

- Browser family
- Operating system family
- Device type (mobile/tablet/desktop)

New Location Detection
----------------------

Alerts users when they log in from a new geographic location.

**How it works:**

1. On each login, the IP address is geolocated
2. The location is compared against the user's known locations
3. If new, an email alert is sent and the location is recorded
4. The login proceeds normally (location detection doesn't block access)

**Location Fingerprint:**

A hash of:

- Country
- City

Known Devices API
-----------------

View devices that have accessed the account.

.. code-block:: http

    GET /security/devices
    Authorization: Bearer <access_token>

**Response:**

.. code-block:: json

    {
        "devices": [
            {
                "uuid": "device-uuid",
                "device_type": "desktop",
                "browser": "Chrome",
                "os": "macOS",
                "device_brand": "Apple",
                "device_model": null,
                "friendly_name": "Chrome on macOS",
                "first_seen_at": "2025-01-01T00:00:00Z",
                "last_seen_at": "2025-01-15T10:00:00Z",
                "is_trusted": true
            }
        ],
        "total": 1
    }

Known Locations API
-------------------

View locations from which the account has been accessed.

.. code-block:: http

    GET /security/locations
    Authorization: Bearer <access_token>

**Response:**

.. code-block:: json

    {
        "locations": [
            {
                "uuid": "location-uuid",
                "country": "United States",
                "city": "San Francisco",
                "region": "California",
                "first_seen_at": "2025-01-01T00:00:00Z",
                "last_seen_at": "2025-01-15T10:00:00Z",
                "is_trusted": true
            }
        ],
        "total": 1
    }

Security Audit Log
------------------

Comprehensive logging of security-relevant events.

Query Audit Log
^^^^^^^^^^^^^^^

.. code-block:: http

    GET /security/audit-log
    Authorization: Bearer <access_token>

**Query Parameters:**

- ``event_types`` (list): Filter by event types
- ``start_date`` (datetime): Filter from date
- ``end_date`` (datetime): Filter to date
- ``success_only`` (bool): Filter by success/failure
- ``page`` (int): Page number
- ``page_size`` (int): Items per page (max 100)

**Response:**

.. code-block:: json

    {
        "logs": [
            {
                "uuid": "log-uuid",
                "event_type": "login_success",
                "event_timestamp": "2025-01-15T10:00:00Z",
                "ip_address": "203.0.113.42",
                "country": "United States",
                "city": "San Francisco",
                "success": true,
                "failure_reason": null,
                "event_data": {}
            }
        ],
        "total": 100,
        "page": 1,
        "page_size": 50
    }

Tracked Event Types
^^^^^^^^^^^^^^^^^^^

**Authentication Events:**

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - Event Type
     - Description
   * - ``login_success``
     - Successful login
   * - ``login_failed``
     - Failed login attempt (wrong password)
   * - ``login_blocked``
     - Login blocked (account inactive, expired, etc.)
   * - ``logout``
     - User logged out
   * - ``logout_all``
     - User logged out of all sessions

**Token Events:**

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - Event Type
     - Description
   * - ``token_refresh``
     - Access token refreshed
   * - ``token_revoked``
     - Token manually revoked

**Session Events:**

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - Event Type
     - Description
   * - ``session_created``
     - New session created
   * - ``session_revoked``
     - Session revoked

**Password Events:**

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - Event Type
     - Description
   * - ``password_changed``
     - Password changed
   * - ``password_reset_requested``
     - Password reset requested
   * - ``password_reset_completed``
     - Password reset completed

**TOTP Events:**

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - Event Type
     - Description
   * - ``totp_enabled``
     - TOTP enabled
   * - ``totp_disabled``
     - TOTP disabled
   * - ``totp_verified``
     - TOTP code verified
   * - ``totp_failed``
     - TOTP verification failed
   * - ``recovery_code_used``
     - Recovery code used
   * - ``recovery_codes_regenerated``
     - Recovery codes regenerated

**Email Events:**

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - Event Type
     - Description
   * - ``email_verified``
     - Email address verified
   * - ``email_verification_requested``
     - Verification email sent

**Device/Location Events:**

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - Event Type
     - Description
   * - ``new_device_login``
     - Login from new device
   * - ``new_location_login``
     - Login from new location

**OAuth Events:**

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - Event Type
     - Description
   * - ``oauth_login``
     - OAuth login
   * - ``oauth_account_linked``
     - OAuth account linked
   * - ``oauth_account_unlinked``
     - OAuth account unlinked

**Account Events:**

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - Event Type
     - Description
   * - ``account_created``
     - Account created
   * - ``account_deleted``
     - Account deleted

Password Security
-----------------

Argon2id Hashing
^^^^^^^^^^^^^^^^

Passwords are hashed with Argon2id, the winner of the Password Hashing Competition.

**Parameters:**

- ``time_cost``: 3 (iterations)
- ``memory_cost``: 65536 (64 MB)
- ``parallelism``: 4 (threads)

**Automatic Rehashing:**

If the hashing parameters are changed (e.g., increased for stronger security), passwords are automatically rehashed on the next successful login.

Token Security
--------------

Secure Token Generation
^^^^^^^^^^^^^^^^^^^^^^^

All tokens use ``secrets.token_urlsafe()`` for cryptographic security:

- Magic links
- Password reset tokens
- Email verification tokens
- OAuth state tokens
- Service API keys

Token Versioning
^^^^^^^^^^^^^^^^

Each user has a ``token_version`` field. When incremented (via "logout all"), all previously issued tokens become invalid, even if they haven't expired.

Email Security Notifications
----------------------------

Users receive email alerts for:

- Login from new device
- Login from new location
- Password changed
- Password reset requested
- TOTP enabled/disabled

Example new device alert:

.. code-block:: text

    Subject: New Device Login - Hecate Sentinel

    A new device was used to access your account.

    Device: Chrome on Windows
    Location: San Francisco, United States
    Time: January 15, 2025 at 10:00 AM

    If this was you, no action is needed.
    If you don't recognize this activity, please change your password immediately.
