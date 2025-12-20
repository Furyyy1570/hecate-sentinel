Overview
========

Hecate Sentinel is a comprehensive authentication and authorization service designed for microservice architectures. It provides a complete solution for user identity management, secure authentication, role-based access control, and interservice communication.

Architecture
------------

Hecate Sentinel is built as a standalone service that handles all authentication and authorization concerns for your application ecosystem. Other services in your architecture can delegate user authentication to Hecate Sentinel, eliminating the need to implement auth logic in each service.

.. code-block:: text

    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
    │   Frontend  │     │  Service A  │     │  Service B  │
    └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
           │                   │                   │
           │ Login/Auth        │ Introspect        │ Introspect
           │                   │                   │
           ▼                   ▼                   ▼
    ┌─────────────────────────────────────────────────────┐
    │                   Hecate Sentinel                    │
    │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────────┐  │
    │  │  Auth   │ │  Users  │ │  RBAC   │ │  Sessions │  │
    │  └─────────┘ └─────────┘ └─────────┘ └───────────┘  │
    └──────────────────────────┬──────────────────────────┘
                               │
                               ▼
                        ┌─────────────┐
                        │  PostgreSQL │
                        └─────────────┘

Key Components
--------------

**Authentication Engine**
    Handles user login via multiple methods: username/password, magic links, OAuth providers (Google, Microsoft), and TOTP two-factor authentication.

**Authorization System**
    Role-based access control (RBAC) with groups and granular permissions. Supports real-time permission checks against the database.

**Session Management**
    Tracks active user sessions with device fingerprinting, geolocation, and the ability to view and revoke sessions.

**Security Monitoring**
    Comprehensive audit logging, new device/location detection, and email alerts for suspicious activity.

**Interservice Authentication**
    Token introspection endpoint allows other services to validate user tokens without sharing JWT secrets.

Technology Stack
----------------

- **Framework**: FastAPI (Python 3.14+)
- **Database**: PostgreSQL with async SQLAlchemy
- **Authentication**: JWT tokens with Argon2id password hashing
- **Migrations**: Alembic (auto-run on startup)
- **Containerization**: Docker and Docker Compose

Design Principles
-----------------

**Security First**
    All passwords are hashed with Argon2id. Tokens use cryptographically secure random generation. Sensitive operations are logged for audit purposes.

**Real-time Authorization**
    Permission checks query the database in real-time, ensuring changes take effect immediately without requiring token refresh.

**Microservice Ready**
    Designed to be the single source of truth for authentication in a distributed system. Services validate tokens via introspection rather than sharing secrets.

**Developer Friendly**
    Auto-generated OpenAPI documentation at ``/docs``. Comprehensive error messages. Pydantic validation for all requests and responses.

**Production Ready**
    Health checks, request ID tracking, CORS configuration, GZip compression, and structured logging out of the box.
