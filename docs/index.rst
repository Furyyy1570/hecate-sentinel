Hecate Sentinel Documentation
=============================

Hecate Sentinel is a comprehensive authentication and authorization service designed for microservice architectures. It provides a complete solution for user identity management, secure authentication, role-based access control, and interservice communication.

.. note::

   This documentation is for Hecate Sentinel version |version|.

Getting Started
---------------

New to Hecate Sentinel? Start here:

1. :doc:`overview` - Understand the architecture and key components
2. :doc:`installation` - Get Hecate Sentinel running
3. :doc:`configuration` - Configure for your environment

.. toctree::
   :maxdepth: 1
   :caption: Introduction
   :hidden:

   overview
   installation
   configuration
   deployment

.. toctree::
   :maxdepth: 2
   :caption: Features
   :hidden:

   features/index

.. toctree::
   :maxdepth: 1
   :caption: Guides
   :hidden:

   api-guide
   interservice

.. toctree::
   :maxdepth: 2
   :caption: API Reference
   :hidden:

   reference/index

Quick Links
-----------

**For Frontend Developers:**

- :doc:`features/authentication` - Login, OAuth, magic links, TOTP
- :doc:`api-guide` - API conventions and examples

**For Backend Developers:**

- :doc:`features/authorization` - Groups, permissions, and the Authorize dependency
- :doc:`interservice` - Validate tokens from other services

**For DevOps/SRE:**

- :doc:`deployment` - Production deployment guide
- :doc:`configuration` - All configuration options

Key Features
------------

**Authentication:**

- Username/password with Argon2id hashing
- Magic link (passwordless) authentication
- OAuth 2.0 (Google, Microsoft)
- Two-factor authentication (TOTP)
- Email verification

**Authorization:**

- Role-based access control (RBAC)
- Granular permissions
- Real-time permission checks
- Admin bypass

**Security:**

- Session management with device/location tracking
- New device/location email alerts
- Comprehensive audit logging
- Secure password reset flow

**Microservices:**

- Token introspection endpoint
- Service API key management
- No JWT secret sharing required

Default Admin Credentials
-------------------------

On first startup, Hecate Sentinel creates an admin user:

- **Username:** ``admin``
- **Email:** ``admin@example.com``
- **Password:** ``admin1234qwer``

.. warning::

   Change these credentials immediately in production!

Indices and Tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
