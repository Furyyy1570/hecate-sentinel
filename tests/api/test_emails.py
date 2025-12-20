"""Tests for emails API endpoints."""

import pytest


@pytest.fixture
async def user_with_email(db_session, test_user):
    """Create a test user with an email."""
    from src.models.email import Email

    email = Email(
        user_id=test_user.id,
        email_address="user@example.com",
        is_primary=True,
        is_verified=False,
    )
    db_session.add(email)
    await db_session.commit()
    await db_session.refresh(email)
    return test_user, email


class TestEmailsListEmails:
    """Tests for GET /users/{user_uuid}/emails."""

    @pytest.mark.asyncio
    async def test_list_emails(self, client, user_with_email):
        """Test listing user emails."""
        user, email = user_with_email

        response = await client.get(f"/users/{user.uuid}/emails")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["email_address"] == "user@example.com"

    @pytest.mark.asyncio
    async def test_list_emails_user_not_found(self, client):
        """Test listing emails for non-existent user."""
        response = await client.get("/users/00000000-0000-0000-0000-000000000000/emails")

        assert response.status_code == 404


class TestEmailsGetEmail:
    """Tests for GET /users/{user_uuid}/emails/{email_uuid}."""

    @pytest.mark.asyncio
    async def test_get_email(self, client, user_with_email):
        """Test getting a specific email."""
        user, email = user_with_email

        response = await client.get(f"/users/{user.uuid}/emails/{email.uuid}")

        assert response.status_code == 200
        data = response.json()
        assert data["email_address"] == "user@example.com"

    @pytest.mark.asyncio
    async def test_get_email_not_found(self, client, test_user):
        """Test getting non-existent email."""
        response = await client.get(
            f"/users/{test_user.uuid}/emails/00000000-0000-0000-0000-000000000000"
        )

        assert response.status_code == 404


class TestEmailsCreateEmail:
    """Tests for POST /users/{user_uuid}/emails."""

    @pytest.mark.asyncio
    async def test_create_email(self, client, test_user):
        """Test creating an email."""
        response = await client.post(
            f"/users/{test_user.uuid}/emails",
            json={
                "email_address": "new@example.com",
                "is_primary": False,
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["email_address"] == "new@example.com"

    @pytest.mark.asyncio
    async def test_create_email_duplicate(self, client, user_with_email):
        """Test creating duplicate email."""
        user, email = user_with_email

        response = await client.post(
            f"/users/{user.uuid}/emails",
            json={
                "email_address": "user@example.com",
                "is_primary": False,
            },
        )

        assert response.status_code == 409
        assert "exists" in response.json()["detail"].lower()


class TestEmailsUpdateEmail:
    """Tests for PATCH /users/{user_uuid}/emails/{email_uuid}."""

    @pytest.mark.asyncio
    async def test_update_email(self, client, user_with_email):
        """Test updating an email."""
        user, email = user_with_email

        response = await client.patch(
            f"/users/{user.uuid}/emails/{email.uuid}",
            json={"email_address": "updated@example.com"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["email_address"] == "updated@example.com"

    @pytest.mark.asyncio
    async def test_update_email_not_found(self, client, test_user):
        """Test updating non-existent email."""
        response = await client.patch(
            f"/users/{test_user.uuid}/emails/00000000-0000-0000-0000-000000000000",
            json={"email_address": "new@example.com"},
        )

        assert response.status_code == 404


class TestEmailsDeleteEmail:
    """Tests for DELETE /users/{user_uuid}/emails/{email_uuid}."""

    @pytest.mark.asyncio
    async def test_delete_email(self, client, user_with_email):
        """Test deleting an email."""
        user, email = user_with_email

        response = await client.delete(f"/users/{user.uuid}/emails/{email.uuid}")

        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_delete_email_not_found(self, client, test_user):
        """Test deleting non-existent email."""
        response = await client.delete(
            f"/users/{test_user.uuid}/emails/00000000-0000-0000-0000-000000000000"
        )

        assert response.status_code == 404


class TestEmailsSetPrimary:
    """Tests for POST /users/{user_uuid}/emails/{email_uuid}/set-primary."""

    @pytest.mark.asyncio
    async def test_set_primary_email(self, client, user_with_email):
        """Test setting email as primary."""
        user, email = user_with_email

        response = await client.post(f"/users/{user.uuid}/emails/{email.uuid}/set-primary")

        assert response.status_code == 200
        data = response.json()
        assert data["is_primary"] is True

    @pytest.mark.asyncio
    async def test_set_primary_email_not_found(self, client, test_user):
        """Test setting non-existent email as primary."""
        response = await client.post(
            f"/users/{test_user.uuid}/emails/00000000-0000-0000-0000-000000000000/set-primary"
        )

        assert response.status_code == 404
