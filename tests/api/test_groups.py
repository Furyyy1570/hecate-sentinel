"""Tests for groups API endpoints."""

import pytest


@pytest.fixture
async def test_group(db_session):
    """Create a test group."""
    from src.models.group import Group

    group = Group(name="testgroup")
    db_session.add(group)
    await db_session.commit()
    await db_session.refresh(group)
    return group


@pytest.fixture
async def test_permission(db_session):
    """Create a test permission."""
    from src.models.permission import Permission

    permission = Permission(name="test:permission")
    db_session.add(permission)
    await db_session.commit()
    await db_session.refresh(permission)
    return permission


class TestGroupsListGroups:
    """Tests for GET /groups."""

    @pytest.mark.asyncio
    async def test_list_groups(self, client, test_group):
        """Test listing groups."""
        response = await client.get("/groups")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    @pytest.mark.asyncio
    async def test_list_groups_pagination(self, client, test_group):
        """Test listing groups with pagination."""
        response = await client.get("/groups?skip=0&limit=10")

        assert response.status_code == 200


class TestGroupsGetGroup:
    """Tests for GET /groups/{group_uuid}."""

    @pytest.mark.asyncio
    async def test_get_group(self, client, test_group):
        """Test getting a group."""
        response = await client.get(f"/groups/{test_group.uuid}")

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "testgroup"

    @pytest.mark.asyncio
    async def test_get_group_not_found(self, client):
        """Test getting non-existent group."""
        response = await client.get("/groups/00000000-0000-0000-0000-000000000000")

        assert response.status_code == 404


class TestGroupsCreateGroup:
    """Tests for POST /groups."""

    @pytest.mark.asyncio
    async def test_create_group(self, client):
        """Test creating a group."""
        response = await client.post(
            "/groups",
            json={"name": "newgroup"},
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "newgroup"

    @pytest.mark.asyncio
    async def test_create_group_duplicate(self, client, test_group):
        """Test creating duplicate group."""
        response = await client.post(
            "/groups",
            json={"name": "testgroup"},
        )

        assert response.status_code == 409
        assert "exists" in response.json()["detail"].lower()


class TestGroupsUpdateGroup:
    """Tests for PATCH /groups/{group_uuid}."""

    @pytest.mark.asyncio
    async def test_update_group(self, client, test_group):
        """Test updating a group."""
        response = await client.patch(
            f"/groups/{test_group.uuid}",
            json={"name": "updatedgroup"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "updatedgroup"

    @pytest.mark.asyncio
    async def test_update_group_not_found(self, client):
        """Test updating non-existent group."""
        response = await client.patch(
            "/groups/00000000-0000-0000-0000-000000000000",
            json={"name": "newname"},
        )

        assert response.status_code == 404


class TestGroupsDeleteGroup:
    """Tests for DELETE /groups/{group_uuid}."""

    @pytest.mark.asyncio
    async def test_delete_group(self, client, db_session):
        """Test deleting a group."""
        from src.models.group import Group

        group = Group(name="deleteme")
        db_session.add(group)
        await db_session.commit()
        await db_session.refresh(group)

        response = await client.delete(f"/groups/{group.uuid}")

        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_delete_group_not_found(self, client):
        """Test deleting non-existent group."""
        response = await client.delete("/groups/00000000-0000-0000-0000-000000000000")

        assert response.status_code == 404


class TestGroupsUsers:
    """Tests for group user management."""

    @pytest.mark.asyncio
    async def test_list_group_users(self, client, test_group):
        """Test listing group users."""
        response = await client.get(f"/groups/{test_group.uuid}/users")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_add_user_to_group(self, client, test_group, test_user):
        """Test adding user to group."""
        response = await client.post(
            f"/groups/{test_group.uuid}/users",
            json={"user_uuid": str(test_user.uuid)},
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_add_user_to_group_not_found(self, client, test_group):
        """Test adding non-existent user to group."""
        response = await client.post(
            f"/groups/{test_group.uuid}/users",
            json={"user_uuid": "00000000-0000-0000-0000-000000000000"},
        )

        assert response.status_code == 404


class TestGroupsPermissions:
    """Tests for group permission management."""

    @pytest.mark.asyncio
    async def test_list_group_permissions(self, client, test_group):
        """Test listing group permissions."""
        response = await client.get(f"/groups/{test_group.uuid}/permissions")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_add_permission_to_group(self, client, test_group, test_permission):
        """Test adding permission to group."""
        response = await client.post(
            f"/groups/{test_group.uuid}/permissions",
            json={"permission_uuid": str(test_permission.uuid)},
        )

        assert response.status_code == 200
