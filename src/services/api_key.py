"""Service API Key management service."""

import secrets
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.security import hash_password, verify_password
from src.models.service_api_key import ServiceAPIKey


class APIKeyService:
    """Service for managing service API keys."""

    # Prefix for all service API keys
    KEY_PREFIX = "hsk_"

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    def generate_api_key(self) -> str:
        """Generate a new API key."""
        # Generate 32 bytes of randomness, URL-safe base64 encoded
        random_part = secrets.token_urlsafe(32)
        return f"{self.KEY_PREFIX}{random_part}"

    async def create_api_key(
        self,
        name: str,
        description: str | None = None,
    ) -> tuple[ServiceAPIKey, str]:
        """
        Create a new service API key.

        Returns (api_key_record, plaintext_key).
        The plaintext key is only available at creation time.
        """
        # Generate the key
        api_key = self.generate_api_key()

        # Extract prefix for identification (first 12 chars including "hsk_")
        key_prefix = api_key[:12]

        # Hash the key for storage
        key_hash = hash_password(api_key)

        # Create the record
        record = ServiceAPIKey(
            name=name,
            description=description,
            key_hash=key_hash,
            key_prefix=key_prefix,
        )
        self.session.add(record)
        await self.session.flush()
        await self.session.refresh(record)

        return record, api_key

    async def validate_api_key(self, api_key: str) -> ServiceAPIKey | None:
        """
        Validate an API key and return the record if valid.

        Also updates last_used_at timestamp.
        """
        if not api_key.startswith(self.KEY_PREFIX):
            return None

        # Extract prefix for faster lookup
        key_prefix = api_key[:12]

        # Find matching records by prefix
        result = await self.session.execute(
            select(ServiceAPIKey).where(
                ServiceAPIKey.key_prefix == key_prefix,
                ServiceAPIKey.is_active == True,  # noqa: E712
                ServiceAPIKey.is_deleted == False,  # noqa: E712
            )
        )
        records = result.scalars().all()

        # Verify the full key against each matching record
        for record in records:
            if verify_password(api_key, record.key_hash):
                # Check expiration
                if record.expires_at and record.expires_at <= datetime.now(timezone.utc):
                    return None

                # Update last used
                record.last_used_at = datetime.now(timezone.utc)
                return record

        return None

    async def get_api_key_by_name(self, name: str) -> ServiceAPIKey | None:
        """Get an API key record by service name."""
        result = await self.session.execute(
            select(ServiceAPIKey).where(
                ServiceAPIKey.name == name,
                ServiceAPIKey.is_active == True,  # noqa: E712
                ServiceAPIKey.is_deleted == False,  # noqa: E712
            )
        )
        return result.scalar_one_or_none()

    async def list_api_keys(self) -> list[ServiceAPIKey]:
        """List all active API keys."""
        result = await self.session.execute(
            select(ServiceAPIKey).where(
                ServiceAPIKey.is_active == True,  # noqa: E712
                ServiceAPIKey.is_deleted == False,  # noqa: E712
            )
        )
        return list(result.scalars().all())

    async def revoke_api_key(self, name: str) -> bool:
        """Revoke (soft delete) an API key by name."""
        record = await self.get_api_key_by_name(name)
        if not record:
            return False

        record.is_deleted = True
        return True
