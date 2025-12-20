Interservice Authentication
===========================

This guide explains how other microservices can validate user JWT tokens issued by Hecate Sentinel.

Overview
--------

Hecate Sentinel provides a token introspection endpoint that allows other services to validate user tokens without having access to the JWT secret key. This follows a secure service-to-service authentication pattern:

1. Each service gets its own API key from Hecate Sentinel
2. When a user makes a request to Service A with their JWT token, Service A calls Hecate Sentinel's introspection endpoint
3. Hecate Sentinel validates both the service API key and the user token
4. Hecate Sentinel returns the validation result with real-time user roles and permissions

.. code-block:: text

    ┌──────────┐         ┌─────────────┐              ┌──────────────────┐
    │  Client  │         │  Service A  │              │  Hecate Sentinel │
    └────┬─────┘         └──────┬──────┘              └────────┬─────────┘
         │                      │                              │
         │ 1. Request           │                              │
         │    Authorization:    │                              │
         │    Bearer <user-jwt> │                              │
         │─────────────────────>│                              │
         │                      │                              │
         │                      │ 2. POST /auth/introspect     │
         │                      │    Authorization: Bearer     │
         │                      │      <service-api-key>       │
         │                      │    Body: { "token": "..." }  │
         │                      │─────────────────────────────>│
         │                      │                              │
         │                      │                              │ 3. Validate:
         │                      │                              │    - Service API key
         │                      │                              │    - User JWT token
         │                      │                              │    - User status
         │                      │                              │    - Roles/permissions
         │                      │                              │
         │                      │ 4. Response                  │
         │                      │<─────────────────────────────│
         │                      │                              │
         │ 5. Response          │                              │
         │<─────────────────────│                              │

Setup
-----

Step 1: Create a Service API Key
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

An admin user must create an API key for each service that needs to validate tokens.

.. code-block:: bash

    curl -X POST http://localhost:8000/auth/service-keys \
      -H "Authorization: Bearer <admin-jwt-token>" \
      -H "Content-Type: application/json" \
      -d '{
        "name": "billing-service",
        "description": "Billing and invoicing microservice"
      }'

**Response:**

.. code-block:: json

    {
      "name": "billing-service",
      "key_prefix": "hsk_a1b2c3d4",
      "api_key": "hsk_a1b2c3d4e5f6g7h8i9j0..."
    }

.. warning::

    Save the ``api_key`` value securely. It is only shown once at creation time.

Step 2: Configure Your Service
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Store the API key securely in your service's environment:

.. code-block:: bash

    # .env or environment variable
    HECATE_SENTINEL_URL=http://hecate-sentinel:8000
    HECATE_SERVICE_API_KEY=hsk_a1b2c3d4e5f6g7h8i9j0...

Token Introspection
-------------------

Endpoint
^^^^^^^^

.. code-block:: http

    POST /auth/introspect
    Authorization: Bearer <service-api-key>
    Content-Type: application/json

    {
      "token": "<user-jwt-token>"
    }

Valid Token Response
^^^^^^^^^^^^^^^^^^^^

.. code-block:: json

    {
      "valid": true,
      "user_id": "992bee2c-8ef0-4b7a-890a-8e26ac6814f7",
      "username": "john.doe",
      "is_admin": false,
      "roles": ["editors", "reviewers"],
      "permissions": ["posts:read", "posts:write", "comments:read"]
    }

Invalid Token Response
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: json

    {
      "valid": false
    }

A token is considered invalid if:

- The JWT signature is invalid
- The token has expired
- The token type is not "access"
- The user does not exist
- The user is inactive or deleted
- The user's account has expired (``expires_on``)
- The user's email is not verified
- The token has been revoked (logout all sessions)

Integration Examples
--------------------

Python (FastAPI)
^^^^^^^^^^^^^^^^

.. code-block:: python

    import httpx
    from fastapi import Depends, HTTPException, Request
    from pydantic import BaseModel
    import os

    HECATE_SENTINEL_URL = os.getenv("HECATE_SENTINEL_URL", "http://hecate-sentinel:8000")
    HECATE_SERVICE_API_KEY = os.getenv("HECATE_SERVICE_API_KEY")


    class CurrentUser(BaseModel):
        """User information from token introspection."""
        user_id: str
        username: str
        is_admin: bool
        roles: list[str]
        permissions: list[str]


    async def get_current_user(request: Request) -> CurrentUser:
        """
        Validate the user's JWT token via Hecate Sentinel introspection.

        Usage:
            @router.get("/invoices")
            async def list_invoices(user: CurrentUser = Depends(get_current_user)):
                # user.user_id, user.username, user.roles, etc.
                ...
        """
        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid Authorization header"
            )

        user_token = auth_header.split(" ", 1)[1]

        # Call Hecate Sentinel introspection
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{HECATE_SENTINEL_URL}/auth/introspect",
                headers={"Authorization": f"Bearer {HECATE_SERVICE_API_KEY}"},
                json={"token": user_token},
                timeout=10.0
            )

        if response.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail="Authentication service unavailable"
            )

        data = response.json()

        if not data.get("valid"):
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token"
            )

        return CurrentUser(
            user_id=data["user_id"],
            username=data["username"],
            is_admin=data["is_admin"],
            roles=data["roles"],
            permissions=data["permissions"],
        )


    def require_permission(permission: str):
        """
        Dependency that requires a specific permission.

        Usage:
            @router.delete("/posts/{id}")
            async def delete_post(
                id: int,
                user: CurrentUser = Depends(require_permission("posts:delete"))
            ):
                ...
        """
        async def check_permission(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
            if user.is_admin:
                return user
            if permission not in user.permissions:
                raise HTTPException(
                    status_code=403,
                    detail=f"Permission required: {permission}"
                )
            return user
        return check_permission


    def require_role(role: str):
        """
        Dependency that requires a specific role.

        Usage:
            @router.get("/admin/stats")
            async def admin_stats(user: CurrentUser = Depends(require_role("site_admins"))):
                ...
        """
        async def check_role(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
            if user.is_admin:
                return user
            if role not in user.roles:
                raise HTTPException(
                    status_code=403,
                    detail=f"Role required: {role}"
                )
            return user
        return check_role

Node.js (Express)
^^^^^^^^^^^^^^^^^

.. code-block:: javascript

    const axios = require('axios');

    const HECATE_SENTINEL_URL = process.env.HECATE_SENTINEL_URL || 'http://hecate-sentinel:8000';
    const HECATE_SERVICE_API_KEY = process.env.HECATE_SERVICE_API_KEY;

    async function authenticateToken(req, res, next) {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];

      if (!token) {
        return res.status(401).json({ error: 'Missing authorization token' });
      }

      try {
        const response = await axios.post(
          `${HECATE_SENTINEL_URL}/auth/introspect`,
          { token },
          {
            headers: {
              'Authorization': `Bearer ${HECATE_SERVICE_API_KEY}`,
              'Content-Type': 'application/json'
            },
            timeout: 10000
          }
        );

        if (!response.data.valid) {
          return res.status(401).json({ error: 'Invalid or expired token' });
        }

        // Attach user info to request
        req.user = {
          userId: response.data.user_id,
          username: response.data.username,
          isAdmin: response.data.is_admin,
          roles: response.data.roles,
          permissions: response.data.permissions
        };

        next();
      } catch (error) {
        console.error('Introspection error:', error.message);
        return res.status(502).json({ error: 'Authentication service unavailable' });
      }
    }

    // Usage
    app.get('/api/invoices', authenticateToken, (req, res) => {
      console.log(`User ${req.user.username} requesting invoices`);
      // ...
    });

Go
^^

.. code-block:: go

    package auth

    import (
        "bytes"
        "context"
        "encoding/json"
        "net/http"
        "os"
        "strings"
    )

    type User struct {
        UserID      string   `json:"user_id"`
        Username    string   `json:"username"`
        IsAdmin     bool     `json:"is_admin"`
        Roles       []string `json:"roles"`
        Permissions []string `json:"permissions"`
    }

    type introspectRequest struct {
        Token string `json:"token"`
    }

    type introspectResponse struct {
        Valid       bool     `json:"valid"`
        UserID      string   `json:"user_id"`
        Username    string   `json:"username"`
        IsAdmin     bool     `json:"is_admin"`
        Roles       []string `json:"roles"`
        Permissions []string `json:"permissions"`
    }

    func ValidateToken(token string) (*User, error) {
        sentinelURL := os.Getenv("HECATE_SENTINEL_URL")
        apiKey := os.Getenv("HECATE_SERVICE_API_KEY")

        reqBody, _ := json.Marshal(introspectRequest{Token: token})

        req, err := http.NewRequest("POST", sentinelURL+"/auth/introspect", bytes.NewBuffer(reqBody))
        if err != nil {
            return nil, err
        }

        req.Header.Set("Authorization", "Bearer "+apiKey)
        req.Header.Set("Content-Type", "application/json")

        client := &http.Client{}
        resp, err := client.Do(req)
        if err != nil {
            return nil, err
        }
        defer resp.Body.Close()

        var result introspectResponse
        if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
            return nil, err
        }

        if !result.Valid {
            return nil, nil // Invalid token
        }

        return &User{
            UserID:      result.UserID,
            Username:    result.Username,
            IsAdmin:     result.IsAdmin,
            Roles:       result.Roles,
            Permissions: result.Permissions,
        }, nil
    }

    // Middleware example
    func AuthMiddleware(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            authHeader := r.Header.Get("Authorization")
            if !strings.HasPrefix(authHeader, "Bearer ") {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            token := strings.TrimPrefix(authHeader, "Bearer ")
            user, err := ValidateToken(token)
            if err != nil || user == nil {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            // Add user to context
            ctx := context.WithValue(r.Context(), "user", user)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }

Managing Service API Keys
-------------------------

List All Service Keys
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

    curl http://localhost:8000/auth/service-keys \
      -H "Authorization: Bearer <admin-jwt-token>"

**Response:**

.. code-block:: json

    [
      {
        "uuid": "a1b2c3d4-...",
        "name": "billing-service",
        "description": "Billing and invoicing microservice",
        "key_prefix": "hsk_a1b2c3d4",
        "is_active": true
      }
    ]

Revoke a Service Key
^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

    curl -X DELETE http://localhost:8000/auth/service-keys/billing-service \
      -H "Authorization: Bearer <admin-jwt-token>"

After revocation, the service will no longer be able to call the introspection endpoint.

Performance Considerations
--------------------------

Each authenticated request to your service results in an HTTP call to Hecate Sentinel. Consider these optimizations:

Keep Hecate Sentinel Close
^^^^^^^^^^^^^^^^^^^^^^^^^^

Deploy it in the same network/cluster to minimize latency.

Short-lived Caching
^^^^^^^^^^^^^^^^^^^

Cache introspection results for a short period (e.g., 30 seconds) to reduce load:

.. code-block:: python

    from datetime import datetime, timedelta

    _cache = {}
    CACHE_TTL = timedelta(seconds=30)

    async def get_current_user_cached(token: str) -> CurrentUser:
        now = datetime.now()
        if token in _cache:
            user, expires = _cache[token]
            if now < expires:
                return user

        user = await introspect_token(token)
        _cache[token] = (user, now + CACHE_TTL)
        return user

.. warning::

    Caching trades freshness for performance. Role/permission changes won't take effect until the cache expires.

Connection Pooling
^^^^^^^^^^^^^^^^^^

Use HTTP connection pooling for introspection calls:

.. code-block:: python

    # Create a single client instance
    http_client = httpx.AsyncClient(timeout=10.0)

    async def introspect_token(token: str):
        response = await http_client.post(...)

Timeouts
^^^^^^^^

Always set reasonable timeouts to prevent cascading failures.

Security Notes
--------------

1. **Store API keys securely**: Use environment variables or a secrets manager
2. **Rotate keys periodically**: Create new keys and update services before revoking old ones
3. **Use HTTPS in production**: All communication should be encrypted
4. **Real-time validation**: Introspection checks the database, so permission changes take effect immediately
5. **Revoked keys are rejected immediately**: No grace period
