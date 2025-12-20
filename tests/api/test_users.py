"""Tests for users API endpoints."""

import pytest


class TestUsersListUsers:
    """Tests for GET /users."""

    @pytest.mark.asyncio
    async def test_list_users(self, client, test_user):
        """Test listing users."""
        response = await client.get("/users")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    @pytest.mark.asyncio
    async def test_list_users_pagination(self, client, test_user):
        """Test listing users with pagination."""
        response = await client.get("/users?skip=0&limit=10")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestUsersGetUser:
    """Tests for GET /users/{user_uuid}."""

    @pytest.mark.asyncio
    async def test_get_user(self, client, test_user):
        """Test getting a user by UUID."""
        response = await client.get(f"/users/{test_user.uuid}")

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == test_user.username

    @pytest.mark.asyncio
    async def test_get_user_not_found(self, client):
        """Test getting non-existent user."""
        response = await client.get("/users/00000000-0000-0000-0000-000000000000")

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()


class TestUsersCreateUser:
    """Tests for POST /users."""

    @pytest.mark.asyncio
    async def test_create_user(self, client):
        """Test creating a user."""
        response = await client.post(
            "/users",
            json={
                "username": "apiuser",
                "password": "SecurePass123!",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "apiuser"
        assert "uuid" in data

    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(self, client, test_user):
        """Test creating user with duplicate username."""
        response = await client.post(
            "/users",
            json={
                "username": test_user.username,
                "password": "SecurePass123!",
            },
        )

        assert response.status_code == 409
        assert "username" in response.json()["detail"].lower()


class TestUsersUpdateUser:
    """Tests for PATCH /users/{user_uuid}."""

    @pytest.mark.asyncio
    async def test_update_user(self, client, test_user):
        """Test updating a user."""
        response = await client.patch(
            f"/users/{test_user.uuid}",
            json={"username": "updateduser"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "updateduser"

    @pytest.mark.asyncio
    async def test_update_user_not_found(self, client):
        """Test updating non-existent user."""
        response = await client.patch(
            "/users/00000000-0000-0000-0000-000000000000",
            json={"username": "newname"},
        )

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_update_user_duplicate_username(self, client, test_user, test_admin_user):
        """Test updating user with duplicate username."""
        response = await client.patch(
            f"/users/{test_user.uuid}",
            json={"username": test_admin_user.username},
        )

        assert response.status_code == 409
        assert "username" in response.json()["detail"].lower()


class TestUsersDeleteUser:
    """Tests for DELETE /users/{user_uuid}."""

    @pytest.mark.asyncio
    async def test_delete_user(self, client, db_session):
        """Test deleting a user."""
        from src.core.security import hash_password
        from src.models.user import User

        # Create a user to delete
        user = User(
            username="deleteme",
            password=hash_password("password123"),
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        response = await client.delete(f"/users/{user.uuid}")

        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_delete_user_not_found(self, client):
        """Test deleting non-existent user."""
        response = await client.delete("/users/00000000-0000-0000-0000-000000000000")

        assert response.status_code == 404
