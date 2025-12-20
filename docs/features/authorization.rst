Authorization
=============

Hecate Sentinel implements a flexible Role-Based Access Control (RBAC) system with groups and permissions.

Concepts
--------

Groups
^^^^^^

Groups are named collections of users. A user can belong to multiple groups.

**Examples:**

- ``site_admins`` - Full system administrators
- ``editors`` - Content editors
- ``moderators`` - Community moderators
- ``billing_managers`` - Finance team

Permissions
^^^^^^^^^^^

Permissions are granular access rights that define what actions a user can perform.

**Naming Convention:**

Permissions follow a ``resource:action`` pattern:

- ``posts:read`` - Can read posts
- ``posts:write`` - Can create/update posts
- ``posts:delete`` - Can delete posts
- ``users:manage`` - Can manage users

Group-Permission Mapping
^^^^^^^^^^^^^^^^^^^^^^^^

Groups are assigned permissions. When a user belongs to a group, they inherit all permissions assigned to that group.

.. code-block:: text

    ┌─────────────────┐     ┌─────────────────┐
    │     editors     │     │   moderators    │
    └────────┬────────┘     └────────┬────────┘
             │                       │
             ▼                       ▼
    ┌─────────────────┐     ┌─────────────────┐
    │  posts:read     │     │  posts:read     │
    │  posts:write    │     │  comments:delete│
    │  posts:delete   │     │  users:warn     │
    └─────────────────┘     └─────────────────┘

Admin Bypass
^^^^^^^^^^^^

Users with ``is_admin=true`` bypass all role and permission checks. They have unrestricted access to all endpoints.

Real-Time Checks
^^^^^^^^^^^^^^^^

Authorization checks query the database in real-time. When you modify a user's groups or a group's permissions, the changes take effect immediately on the next request.

Using the Authorize Dependency
------------------------------

Hecate Sentinel provides a FastAPI dependency for protecting endpoints.

Basic Authentication
^^^^^^^^^^^^^^^^^^^^

Require a valid, authenticated user:

.. code-block:: python

    from src.api.dependencies import get_current_user
    from src.models.user import User

    @router.get("/profile")
    async def get_profile(user: User = Depends(get_current_user)):
        return {"username": user.username}

Require Specific Roles
^^^^^^^^^^^^^^^^^^^^^^

Require the user to belong to specific groups:

.. code-block:: python

    from src.api.dependencies import Authorize

    @router.get("/editor-dashboard")
    async def editor_dashboard(user: User = Depends(Authorize(roles=["editors"]))):
        return {"message": "Welcome, editor!"}

By default, the user needs to belong to **any** of the specified roles.

Require All Roles
^^^^^^^^^^^^^^^^^

Require the user to belong to **all** specified groups:

.. code-block:: python

    @router.get("/senior-editor")
    async def senior_editor(
        user: User = Depends(Authorize(
            roles=["editors", "senior_staff"],
            require_all_roles=True
        ))
    ):
        return {"message": "Welcome, senior editor!"}

Require Specific Permissions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Require the user to have specific permissions:

.. code-block:: python

    @router.delete("/posts/{post_id}")
    async def delete_post(
        post_id: int,
        user: User = Depends(Authorize(permissions=["posts:delete"]))
    ):
        # Delete the post
        return {"message": "Post deleted"}

Require All Permissions
^^^^^^^^^^^^^^^^^^^^^^^

Require the user to have **all** specified permissions:

.. code-block:: python

    @router.put("/users/{user_id}")
    async def update_user(
        user_id: str,
        user: User = Depends(Authorize(
            permissions=["users:read", "users:write"],
            require_all_permissions=True
        ))
    ):
        # Update the user
        return {"message": "User updated"}

Combine Roles and Permissions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can require both roles and permissions:

.. code-block:: python

    @router.post("/publish")
    async def publish_content(
        user: User = Depends(Authorize(
            roles=["editors"],
            permissions=["content:publish"]
        ))
    ):
        # Publish content
        return {"message": "Published"}

Managing Groups
---------------

List Groups
^^^^^^^^^^^

.. code-block:: http

    GET /groups
    Authorization: Bearer <access_token>

**Response:**

.. code-block:: json

    {
        "items": [
            {
                "uuid": "abc-123",
                "name": "editors",
                "description": "Content editors"
            }
        ],
        "total": 1,
        "page": 1,
        "page_size": 50
    }

Create Group
^^^^^^^^^^^^

.. code-block:: http

    POST /groups
    Authorization: Bearer <admin_token>
    Content-Type: application/json

    {
        "name": "reviewers",
        "description": "Content reviewers"
    }

Get Group Details
^^^^^^^^^^^^^^^^^

.. code-block:: http

    GET /groups/{uuid}
    Authorization: Bearer <access_token>

Update Group
^^^^^^^^^^^^

.. code-block:: http

    PUT /groups/{uuid}
    Authorization: Bearer <admin_token>
    Content-Type: application/json

    {
        "description": "Updated description"
    }

Delete Group
^^^^^^^^^^^^

.. code-block:: http

    DELETE /groups/{uuid}
    Authorization: Bearer <admin_token>

Managing Group Members
----------------------

List Group Members
^^^^^^^^^^^^^^^^^^

.. code-block:: http

    GET /groups/{uuid}/users
    Authorization: Bearer <access_token>

Add User to Group
^^^^^^^^^^^^^^^^^

.. code-block:: http

    POST /groups/{uuid}/users/{user_uuid}
    Authorization: Bearer <admin_token>

Remove User from Group
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

    DELETE /groups/{uuid}/users/{user_uuid}
    Authorization: Bearer <admin_token>

Managing Group Permissions
--------------------------

List Group Permissions
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

    GET /groups/{uuid}/permissions
    Authorization: Bearer <access_token>

Add Permission to Group
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

    POST /groups/{uuid}/permissions/{permission_uuid}
    Authorization: Bearer <admin_token>

Remove Permission from Group
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

    DELETE /groups/{uuid}/permissions/{permission_uuid}
    Authorization: Bearer <admin_token>

Managing Permissions
--------------------

List Permissions
^^^^^^^^^^^^^^^^

.. code-block:: http

    GET /permissions
    Authorization: Bearer <access_token>

Create Permission
^^^^^^^^^^^^^^^^^

.. code-block:: http

    POST /permissions
    Authorization: Bearer <admin_token>
    Content-Type: application/json

    {
        "name": "posts:archive",
        "description": "Can archive posts"
    }

Get Permission Details
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

    GET /permissions/{uuid}
    Authorization: Bearer <access_token>

Update Permission
^^^^^^^^^^^^^^^^^

.. code-block:: http

    PUT /permissions/{uuid}
    Authorization: Bearer <admin_token>
    Content-Type: application/json

    {
        "description": "Can archive and unarchive posts"
    }

Delete Permission
^^^^^^^^^^^^^^^^^

.. code-block:: http

    DELETE /permissions/{uuid}
    Authorization: Bearer <admin_token>

Best Practices
--------------

1. **Use descriptive names**: ``posts:delete`` is better than ``pd`` or ``delete``.

2. **Keep permissions granular**: Prefer ``users:read`` and ``users:write`` over ``users:manage``.

3. **Avoid role explosion**: Use permissions for fine-grained control, roles for logical groupings.

4. **Audit regularly**: Review group memberships and permissions periodically.

5. **Limit admin users**: Only grant ``is_admin=true`` to users who truly need unrestricted access.
