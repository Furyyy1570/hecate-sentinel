"""Tests for permissions API endpoints."""

import pytest


@pytest.fixture
async def test_permission(db_session):
    """Create a test permission."""
    from src.models.permission import Permission

    permission = Permission(name="test:read")
    db_session.add(permission)
    await db_session.commit()
    await db_session.refresh(permission)
    return permission


class TestPermissionsListPermissions:
    """Tests for GET /permissions."""

    @pytest.mark.asyncio
    async def test_list_permissions(self, client, test_permission):
        """Test listing permissions."""
        response = await client.get("/permissions")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    @pytest.mark.asyncio
    async def test_list_permissions_pagination(self, client, test_permission):
        """Test listing permissions with pagination."""
        response = await client.get("/permissions?skip=0&limit=10")

        assert response.status_code == 200


class TestPermissionsGetPermission:
    """Tests for GET /permissions/{permission_uuid}."""

    @pytest.mark.asyncio
    async def test_get_permission(self, client, test_permission):
        """Test getting a permission."""
        response = await client.get(f"/permissions/{test_permission.uuid}")

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "test:read"

    @pytest.mark.asyncio
    async def test_get_permission_not_found(self, client):
        """Test getting non-existent permission."""
        response = await client.get("/permissions/00000000-0000-0000-0000-000000000000")

        assert response.status_code == 404


class TestPermissionsCreatePermission:
    """Tests for POST /permissions."""

    @pytest.mark.asyncio
    async def test_create_permission(self, client):
        """Test creating a permission."""
        response = await client.post(
            "/permissions",
            json={"name": "test:write"},
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "test:write"

    @pytest.mark.asyncio
    async def test_create_permission_duplicate(self, client, test_permission):
        """Test creating duplicate permission."""
        response = await client.post(
            "/permissions",
            json={"name": "test:read"},
        )

        assert response.status_code == 409
        assert "exists" in response.json()["detail"].lower()


class TestPermissionsUpdatePermission:
    """Tests for PATCH /permissions/{permission_uuid}."""

    @pytest.mark.asyncio
    async def test_update_permission(self, client, test_permission):
        """Test updating a permission."""
        response = await client.patch(
            f"/permissions/{test_permission.uuid}",
            json={"name": "test:updated"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "test:updated"

    @pytest.mark.asyncio
    async def test_update_permission_not_found(self, client):
        """Test updating non-existent permission."""
        response = await client.patch(
            "/permissions/00000000-0000-0000-0000-000000000000",
            json={"name": "new:name"},
        )

        assert response.status_code == 404


class TestPermissionsDeletePermission:
    """Tests for DELETE /permissions/{permission_uuid}."""

    @pytest.mark.asyncio
    async def test_delete_permission(self, client, db_session):
        """Test deleting a permission."""
        from src.models.permission import Permission

        permission = Permission(name="delete:me")
        db_session.add(permission)
        await db_session.commit()
        await db_session.refresh(permission)

        response = await client.delete(f"/permissions/{permission.uuid}")

        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_delete_permission_not_found(self, client):
        """Test deleting non-existent permission."""
        response = await client.delete("/permissions/00000000-0000-0000-0000-000000000000")

        assert response.status_code == 404
