User Management
===============

Hecate Sentinel provides comprehensive user lifecycle management.

User CRUD Operations
--------------------

List Users
^^^^^^^^^^

.. code-block:: http

    GET /users
    Authorization: Bearer <access_token>

**Query Parameters:**

- ``page`` (int): Page number (default: 1)
- ``page_size`` (int): Items per page (default: 50, max: 100)

**Response:**

.. code-block:: json

    {
        "items": [
            {
                "uuid": "abc-123",
                "username": "johndoe",
                "is_admin": false,
                "is_active": true,
                "expires_on": null,
                "pub_date": "2025-01-01T00:00:00Z",
                "mod_date": "2025-01-01T00:00:00Z"
            }
        ],
        "total": 100,
        "page": 1,
        "page_size": 50
    }

Create User
^^^^^^^^^^^

.. code-block:: http

    POST /users
    Authorization: Bearer <admin_token>
    Content-Type: application/json

    {
        "username": "newuser",
        "password": "secure_password",
        "email": "newuser@example.com",
        "is_admin": false
    }

**Response:**

.. code-block:: json

    {
        "uuid": "new-uuid",
        "username": "newuser",
        "is_admin": false,
        "is_active": true,
        "expires_on": null
    }

Get User Details
^^^^^^^^^^^^^^^^

.. code-block:: http

    GET /users/{uuid}
    Authorization: Bearer <access_token>

Update User
^^^^^^^^^^^

.. code-block:: http

    PUT /users/{uuid}
    Authorization: Bearer <admin_token>
    Content-Type: application/json

    {
        "username": "updated_username",
        "is_admin": false,
        "is_active": true
    }

Delete User (Soft Delete)
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

    DELETE /users/{uuid}
    Authorization: Bearer <admin_token>

**Note:** Users are soft-deleted (``is_deleted=true``), not permanently removed.

User Account Expiration
-----------------------

Support for temporary and external users through the ``expires_on`` field.

**Features:**

- Optional expiration datetime
- Automatic deactivation when expiration is reached
- Checked on every authentication

Set User Expiration
^^^^^^^^^^^^^^^^^^^

.. code-block:: http

    PUT /users/{uuid}
    Authorization: Bearer <admin_token>
    Content-Type: application/json

    {
        "expires_on": "2025-06-30T23:59:59Z"
    }

**Behavior:**

- When a user's expiration date passes, ``is_active`` is automatically set to ``false`` on their next authentication attempt.
- Expired users cannot log in or use refresh tokens.

Remove Expiration
^^^^^^^^^^^^^^^^^

.. code-block:: http

    PUT /users/{uuid}
    Authorization: Bearer <admin_token>
    Content-Type: application/json

    {
        "expires_on": null
    }

Multiple Emails per User
------------------------

Users can have multiple email addresses associated with their account.

**Features:**

- Primary email designation
- Email verification status per address
- Unique constraint (no email can belong to multiple users)

List User's Emails
^^^^^^^^^^^^^^^^^^

.. code-block:: http

    GET /users/{uuid}/emails
    Authorization: Bearer <access_token>

**Response:**

.. code-block:: json

    {
        "items": [
            {
                "uuid": "email-uuid",
                "email_address": "primary@example.com",
                "is_primary": true,
                "is_verified": true
            },
            {
                "uuid": "email-uuid-2",
                "email_address": "secondary@example.com",
                "is_primary": false,
                "is_verified": false
            }
        ],
        "total": 2
    }

Add Email
^^^^^^^^^

.. code-block:: http

    POST /users/{uuid}/emails
    Authorization: Bearer <access_token>
    Content-Type: application/json

    {
        "email_address": "new@example.com"
    }

A verification email is sent automatically.

Get Email Details
^^^^^^^^^^^^^^^^^

.. code-block:: http

    GET /users/{uuid}/emails/{email_uuid}
    Authorization: Bearer <access_token>

Update Email
^^^^^^^^^^^^

.. code-block:: http

    PUT /users/{uuid}/emails/{email_uuid}
    Authorization: Bearer <access_token>
    Content-Type: application/json

    {
        "email_address": "updated@example.com"
    }

Delete Email
^^^^^^^^^^^^

.. code-block:: http

    DELETE /users/{uuid}/emails/{email_uuid}
    Authorization: Bearer <access_token>

**Note:** Cannot delete the primary email if it's the only email.

Set Primary Email
^^^^^^^^^^^^^^^^^

.. code-block:: http

    POST /users/{uuid}/emails/{email_uuid}/set-primary
    Authorization: Bearer <access_token>

**Note:** The email must be verified to be set as primary.

Phone Numbers
-------------

Optional phone number management for users.

List User's Phones
^^^^^^^^^^^^^^^^^^

.. code-block:: http

    GET /users/{uuid}/phones
    Authorization: Bearer <access_token>

Add Phone
^^^^^^^^^

.. code-block:: http

    POST /users/{uuid}/phones
    Authorization: Bearer <access_token>
    Content-Type: application/json

    {
        "phone_number": "+1234567890"
    }

Get Phone Details
^^^^^^^^^^^^^^^^^

.. code-block:: http

    GET /users/{uuid}/phones/{phone_uuid}
    Authorization: Bearer <access_token>

Update Phone
^^^^^^^^^^^^

.. code-block:: http

    PUT /users/{uuid}/phones/{phone_uuid}
    Authorization: Bearer <access_token>
    Content-Type: application/json

    {
        "phone_number": "+0987654321"
    }

Delete Phone
^^^^^^^^^^^^

.. code-block:: http

    DELETE /users/{uuid}/phones/{phone_uuid}
    Authorization: Bearer <access_token>

Set Primary Phone
^^^^^^^^^^^^^^^^^

.. code-block:: http

    POST /users/{uuid}/phones/{phone_uuid}/set-primary
    Authorization: Bearer <access_token>

OAuth Account Linking
---------------------

Manage linked OAuth provider accounts.

List Linked Accounts
^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

    GET /users/{uuid}/oauth-accounts
    Authorization: Bearer <access_token>

**Response:**

.. code-block:: json

    {
        "items": [
            {
                "uuid": "oauth-uuid",
                "provider": "google",
                "provider_user_id": "123456789",
                "provider_email": "user@gmail.com",
                "pub_date": "2025-01-01T00:00:00Z"
            }
        ],
        "total": 1
    }

Unlink Account
^^^^^^^^^^^^^^

.. code-block:: http

    DELETE /users/{uuid}/oauth-accounts/{oauth_uuid}
    Authorization: Bearer <access_token>

**Note:** Users must have at least one authentication method (password or OAuth account) to unlink.

Data Model
----------

User Fields
^^^^^^^^^^^

.. list-table::
   :widths: 20 20 60
   :header-rows: 1

   * - Field
     - Type
     - Description
   * - ``uuid``
     - UUID
     - Public unique identifier
   * - ``username``
     - String
     - Unique username
   * - ``password``
     - String
     - Argon2id hashed password
   * - ``is_admin``
     - Boolean
     - Admin flag (bypasses all permission checks)
   * - ``is_active``
     - Boolean
     - Account active status
   * - ``is_deleted``
     - Boolean
     - Soft delete flag
   * - ``expires_on``
     - DateTime
     - Optional account expiration
   * - ``totp_secret``
     - String
     - Encrypted TOTP secret (if enabled)
   * - ``token_version``
     - Integer
     - Incremented to revoke all tokens
   * - ``pub_date``
     - DateTime
     - Creation timestamp
   * - ``mod_date``
     - DateTime
     - Last modification timestamp
