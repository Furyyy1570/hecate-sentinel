"""Tests for phones API endpoints."""

import pytest


@pytest.fixture
async def user_with_phone(db_session, test_user):
    """Create a test user with a phone."""
    from src.models.phone import Phone

    phone = Phone(
        user_id=test_user.id,
        phone_number="+1234567890",
        is_primary=True,
        is_verified=False,
    )
    db_session.add(phone)
    await db_session.commit()
    await db_session.refresh(phone)
    return test_user, phone


class TestPhonesListPhones:
    """Tests for GET /users/{user_uuid}/phones."""

    @pytest.mark.asyncio
    async def test_list_phones(self, client, user_with_phone):
        """Test listing user phones."""
        user, phone = user_with_phone

        response = await client.get(f"/users/{user.uuid}/phones")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["phone_number"] == "+1234567890"

    @pytest.mark.asyncio
    async def test_list_phones_user_not_found(self, client):
        """Test listing phones for non-existent user."""
        response = await client.get("/users/00000000-0000-0000-0000-000000000000/phones")

        assert response.status_code == 404


class TestPhonesGetPhone:
    """Tests for GET /users/{user_uuid}/phones/{phone_uuid}."""

    @pytest.mark.asyncio
    async def test_get_phone(self, client, user_with_phone):
        """Test getting a specific phone."""
        user, phone = user_with_phone

        response = await client.get(f"/users/{user.uuid}/phones/{phone.uuid}")

        assert response.status_code == 200
        data = response.json()
        assert data["phone_number"] == "+1234567890"

    @pytest.mark.asyncio
    async def test_get_phone_not_found(self, client, test_user):
        """Test getting non-existent phone."""
        response = await client.get(
            f"/users/{test_user.uuid}/phones/00000000-0000-0000-0000-000000000000"
        )

        assert response.status_code == 404


class TestPhonesCreatePhone:
    """Tests for POST /users/{user_uuid}/phones."""

    @pytest.mark.asyncio
    async def test_create_phone(self, client, test_user):
        """Test creating a phone."""
        response = await client.post(
            f"/users/{test_user.uuid}/phones",
            json={
                "phone_number": "+9876543210",
                "is_primary": False,
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["phone_number"] == "+9876543210"

    @pytest.mark.asyncio
    async def test_create_phone_duplicate(self, client, user_with_phone):
        """Test creating duplicate phone."""
        user, phone = user_with_phone

        response = await client.post(
            f"/users/{user.uuid}/phones",
            json={
                "phone_number": "+1234567890",
                "is_primary": False,
            },
        )

        assert response.status_code == 409
        assert "exists" in response.json()["detail"].lower()


class TestPhonesUpdatePhone:
    """Tests for PATCH /users/{user_uuid}/phones/{phone_uuid}."""

    @pytest.mark.asyncio
    async def test_update_phone(self, client, user_with_phone):
        """Test updating a phone."""
        user, phone = user_with_phone

        response = await client.patch(
            f"/users/{user.uuid}/phones/{phone.uuid}",
            json={"phone_number": "+1111111111"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["phone_number"] == "+1111111111"

    @pytest.mark.asyncio
    async def test_update_phone_not_found(self, client, test_user):
        """Test updating non-existent phone."""
        response = await client.patch(
            f"/users/{test_user.uuid}/phones/00000000-0000-0000-0000-000000000000",
            json={"phone_number": "+1111111111"},
        )

        assert response.status_code == 404


class TestPhonesDeletePhone:
    """Tests for DELETE /users/{user_uuid}/phones/{phone_uuid}."""

    @pytest.mark.asyncio
    async def test_delete_phone(self, client, user_with_phone):
        """Test deleting a phone."""
        user, phone = user_with_phone

        response = await client.delete(f"/users/{user.uuid}/phones/{phone.uuid}")

        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_delete_phone_not_found(self, client, test_user):
        """Test deleting non-existent phone."""
        response = await client.delete(
            f"/users/{test_user.uuid}/phones/00000000-0000-0000-0000-000000000000"
        )

        assert response.status_code == 404


class TestPhonesSetPrimary:
    """Tests for POST /users/{user_uuid}/phones/{phone_uuid}/set-primary."""

    @pytest.mark.asyncio
    async def test_set_primary_phone(self, client, user_with_phone):
        """Test setting phone as primary."""
        user, phone = user_with_phone

        response = await client.post(f"/users/{user.uuid}/phones/{phone.uuid}/set-primary")

        assert response.status_code == 200
        data = response.json()
        assert data["is_primary"] is True

    @pytest.mark.asyncio
    async def test_set_primary_phone_not_found(self, client, test_user):
        """Test setting non-existent phone as primary."""
        response = await client.post(
            f"/users/{test_user.uuid}/phones/00000000-0000-0000-0000-000000000000/set-primary"
        )

        assert response.status_code == 404
