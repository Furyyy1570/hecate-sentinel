Deployment
==========

This guide covers deploying Hecate Sentinel to production environments.

Docker Compose (Recommended)
----------------------------

The simplest production deployment uses Docker Compose.

1. **Prepare the environment file**:

   .. code-block:: bash

       # Copy example and edit
       cp .env.example .env.production

       # Generate a secure secret key
       python -c "import secrets; print(secrets.token_urlsafe(32))"

2. **Configure production settings** in ``.env.production``:

   .. code-block:: text

       # Required
       SECRET_KEY=your-secure-secret-key
       DB_PASSWORD=your-secure-db-password

       # Recommended
       ENVIRONMENT=production
       DEBUG=false
       LOG_LEVEL=INFO

       # SMTP for email notifications
       SMTP_HOST=smtp.your-provider.com
       SMTP_PORT=587
       SMTP_USERNAME=your-username
       SMTP_PASSWORD=your-password
       SMTP_FROM_EMAIL=auth@yourdomain.com

       # Frontend URL for email links
       FRONTEND_URL=https://app.yourdomain.com
       CORS_ORIGINS=["https://app.yourdomain.com"]

3. **Start the services**:

   .. code-block:: bash

       docker compose --env-file .env.production up -d

4. **Verify deployment**:

   .. code-block:: bash

       # Check health
       curl http://localhost:8000/health

       # Check logs
       docker compose logs -f api

Reverse Proxy Setup
-------------------

In production, run Hecate Sentinel behind a reverse proxy for TLS termination and load balancing.

Nginx Configuration
^^^^^^^^^^^^^^^^^^^

.. code-block:: nginx

    upstream hecate_sentinel {
        server 127.0.0.1:8000;
        keepalive 32;
    }

    server {
        listen 443 ssl http2;
        server_name api.yourdomain.com;

        ssl_certificate /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;

        # Security headers
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;

        location / {
            proxy_pass http://hecate_sentinel;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header Connection "";

            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }
    }

    server {
        listen 80;
        server_name api.yourdomain.com;
        return 301 https://$server_name$request_uri;
    }

Traefik Configuration
^^^^^^^^^^^^^^^^^^^^^

If using Traefik, add labels to your ``docker-compose.yml``:

.. code-block:: yaml

    services:
      api:
        labels:
          - "traefik.enable=true"
          - "traefik.http.routers.hecate.rule=Host(`api.yourdomain.com`)"
          - "traefik.http.routers.hecate.tls=true"
          - "traefik.http.routers.hecate.tls.certresolver=letsencrypt"
          - "traefik.http.services.hecate.loadbalancer.server.port=8000"

Kubernetes Deployment
---------------------

For Kubernetes deployments, use the following manifests as a starting point.

Deployment
^^^^^^^^^^

.. code-block:: yaml

    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: hecate-sentinel
    spec:
      replicas: 3
      selector:
        matchLabels:
          app: hecate-sentinel
      template:
        metadata:
          labels:
            app: hecate-sentinel
        spec:
          containers:
          - name: api
            image: your-registry/hecate-sentinel:latest
            ports:
            - containerPort: 8000
            envFrom:
            - secretRef:
                name: hecate-sentinel-secrets
            - configMapRef:
                name: hecate-sentinel-config
            readinessProbe:
              httpGet:
                path: /health
                port: 8000
              initialDelaySeconds: 5
              periodSeconds: 10
            livenessProbe:
              httpGet:
                path: /health
                port: 8000
              initialDelaySeconds: 15
              periodSeconds: 20
            resources:
              requests:
                cpu: "100m"
                memory: "256Mi"
              limits:
                cpu: "1000m"
                memory: "1Gi"

Service
^^^^^^^

.. code-block:: yaml

    apiVersion: v1
    kind: Service
    metadata:
      name: hecate-sentinel
    spec:
      selector:
        app: hecate-sentinel
      ports:
      - port: 80
        targetPort: 8000

ConfigMap and Secrets
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: yaml

    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: hecate-sentinel-config
    data:
      ENVIRONMENT: "production"
      DEBUG: "false"
      LOG_LEVEL: "INFO"
      DB_HOST: "postgres.default.svc.cluster.local"
      DB_PORT: "5432"
      DB_NAME: "hecate_sentinel"
      FRONTEND_URL: "https://app.yourdomain.com"
    ---
    apiVersion: v1
    kind: Secret
    metadata:
      name: hecate-sentinel-secrets
    type: Opaque
    stringData:
      SECRET_KEY: "your-secret-key"
      DB_USER: "hecate"
      DB_PASSWORD: "your-db-password"

Database Considerations
-----------------------

PostgreSQL Setup
^^^^^^^^^^^^^^^^

For production, consider:

- **Connection Pooling**: Use PgBouncer for high-traffic deployments
- **Replication**: Set up read replicas for read-heavy workloads
- **Backups**: Configure automated backups with point-in-time recovery
- **Monitoring**: Use pg_stat_statements for query analysis

Recommended PostgreSQL settings:

.. code-block:: text

    # postgresql.conf
    max_connections = 200
    shared_buffers = 256MB
    work_mem = 16MB
    maintenance_work_mem = 128MB
    effective_cache_size = 768MB

Migrations
^^^^^^^^^^

Migrations run automatically on application startup. For manual control:

.. code-block:: bash

    # Run migrations manually
    uv run alembic upgrade head

    # Check migration status
    uv run alembic current

    # Generate a new migration
    uv run alembic revision --autogenerate -m "description"

Scaling Considerations
----------------------

Horizontal Scaling
^^^^^^^^^^^^^^^^^^

Hecate Sentinel is stateless and can be horizontally scaled. Each instance:

- Connects to the same PostgreSQL database
- Uses JWT tokens (no session affinity required)
- Performs real-time database queries for authorization

**Recommended**: Run 2+ instances behind a load balancer for high availability.

Database Connection Pooling
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Adjust pool settings based on your replica count:

.. code-block:: text

    # Per-instance settings
    DB_POOL_SIZE=5
    DB_MAX_OVERFLOW=10

    # With 3 replicas: 3 * (5 + 10) = 45 max connections
    # Ensure PostgreSQL max_connections > total

Monitoring
----------

Health Checks
^^^^^^^^^^^^^

Use the ``/health`` endpoint for monitoring:

.. code-block:: bash

    curl http://localhost:8000/health
    # {"status": "healthy", "environment": "production"}

Logging
^^^^^^^

Logs are structured and written to stdout. Configure your log aggregator to collect from container stdout.

.. code-block:: json

    {
      "timestamp": "2025-01-15T10:30:00Z",
      "level": "INFO",
      "message": "User login successful",
      "user_id": "abc-123",
      "request_id": "req-456"
    }

Metrics
^^^^^^^

Consider adding Prometheus metrics with ``prometheus-fastapi-instrumentator``:

.. code-block:: bash

    uv add prometheus-fastapi-instrumentator

Security Checklist
------------------

Before going to production, verify:

.. list-table::
   :widths: 10 90
   :header-rows: 0

   * - ☐
     - ``SECRET_KEY`` is a secure, unique random string
   * - ☐
     - ``DEBUG=false``
   * - ☐
     - ``CORS_ORIGINS`` lists only your allowed domains
   * - ☐
     - TLS/HTTPS is enabled via reverse proxy
   * - ☐
     - Database password is strong and unique
   * - ☐
     - Default admin password has been changed
   * - ☐
     - SMTP is configured for email notifications
   * - ☐
     - Firewall rules restrict database access
   * - ☐
     - Container runs as non-root user
   * - ☐
     - Secrets are managed securely (not in version control)
