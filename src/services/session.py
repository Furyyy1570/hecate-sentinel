"""Session management service."""

import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.geoip import GeoLocation, create_location_fingerprint, get_geolocation
from src.core.request_context import RequestContext
from src.core.settings import get_settings
from src.core.user_agent import (
    DeviceInfo,
    create_device_fingerprint,
    get_device_friendly_name,
    parse_user_agent,
)
from src.models.known_device import KnownDevice
from src.models.known_location import KnownLocation
from src.models.session import UserSession
from src.models.user import User

settings = get_settings()


class SessionService:
    """Service for managing user sessions."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_session(
        self,
        user: User,
        refresh_token: str,
        context: RequestContext,
    ) -> tuple[UserSession, bool, bool, GeoLocation, DeviceInfo]:
        """
        Create a new session and detect new device/location.

        Returns (session, is_new_device, is_new_location, geo, device_info).
        """
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=settings.refresh_token_expire_days)

        # Parse device info
        device_info = parse_user_agent(context.user_agent)
        device_fingerprint = create_device_fingerprint(context.user_agent)

        # Get geolocation
        geo = await get_geolocation(context.ip_address)
        location_fingerprint = create_location_fingerprint(geo.country, geo.city)

        # Check for new device
        is_new_device = await self._check_new_device(
            user, device_fingerprint, device_info, context.user_agent, now
        )

        # Check for new location
        is_new_location = await self._check_new_location(
            user, location_fingerprint, geo, now
        )

        # Create session
        user_session = UserSession(
            user_id=user.id,
            refresh_token_hash=self._hash_token(refresh_token),
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            device_type=device_info.device_type,
            browser=device_info.browser,
            browser_version=device_info.browser_version,
            os=device_info.os,
            os_version=device_info.os_version,
            device_brand=device_info.device_brand,
            device_model=device_info.device_model,
            country=geo.country,
            country_code=geo.country_code,
            region=geo.region,
            city=geo.city,
            latitude=geo.latitude,
            longitude=geo.longitude,
            timezone=geo.timezone,
            isp=geo.isp,
            created_at=now,
            last_activity_at=now,
            expires_at=expires_at,
        )
        self.session.add(user_session)
        await self.session.flush()

        return user_session, is_new_device, is_new_location, geo, device_info

    async def _check_new_device(
        self,
        user: User,
        fingerprint: str,
        device_info: DeviceInfo,
        user_agent: str,
        now: datetime,
    ) -> bool:
        """Check if device is new and create/update known device record."""
        result = await self.session.execute(
            select(KnownDevice).where(
                KnownDevice.user_id == user.id,
                KnownDevice.device_fingerprint == fingerprint,
                KnownDevice.is_deleted == False,  # noqa: E712
            )
        )
        known_device = result.scalar_one_or_none()

        if known_device:
            # Update last seen
            known_device.last_seen_at = now
            return False

        # Create new known device
        new_device = KnownDevice(
            user_id=user.id,
            device_fingerprint=fingerprint,
            user_agent=user_agent,
            device_type=device_info.device_type,
            browser=device_info.browser,
            os=device_info.os,
            device_brand=device_info.device_brand,
            device_model=device_info.device_model,
            friendly_name=get_device_friendly_name(device_info),
            first_seen_at=now,
            last_seen_at=now,
            is_trusted=True,
        )
        self.session.add(new_device)
        return True

    async def _check_new_location(
        self,
        user: User,
        fingerprint: str,
        geo: GeoLocation,
        now: datetime,
    ) -> bool:
        """Check if location is new and create/update known location record."""
        # Skip if no location data
        if not geo.country and not geo.city:
            return False

        result = await self.session.execute(
            select(KnownLocation).where(
                KnownLocation.user_id == user.id,
                KnownLocation.location_fingerprint == fingerprint,
                KnownLocation.is_deleted == False,  # noqa: E712
            )
        )
        known_location = result.scalar_one_or_none()

        if known_location:
            # Update last seen
            known_location.last_seen_at = now
            return False

        # Create new known location
        new_location = KnownLocation(
            user_id=user.id,
            location_fingerprint=fingerprint,
            country=geo.country,
            country_code=geo.country_code,
            region=geo.region,
            city=geo.city,
            first_seen_at=now,
            last_seen_at=now,
            is_trusted=True,
        )
        self.session.add(new_location)
        return True

    async def get_active_sessions(
        self, user: User, current_token_hash: str | None = None
    ) -> list[tuple[UserSession, bool]]:
        """Get all active sessions for a user with current session flag."""
        now = datetime.now(timezone.utc)
        result = await self.session.execute(
            select(UserSession)
            .where(
                UserSession.user_id == user.id,
                UserSession.expires_at > now,
                UserSession.revoked_at == None,  # noqa: E711
                UserSession.is_deleted == False,  # noqa: E712
            )
            .order_by(UserSession.last_activity_at.desc())
        )
        sessions = result.scalars().all()

        return [(s, s.refresh_token_hash == current_token_hash) for s in sessions]

    async def revoke_session(self, user: User, session_uuid: str) -> bool:
        """Revoke a specific session."""
        now = datetime.now(timezone.utc)
        result = await self.session.execute(
            select(UserSession).where(
                UserSession.user_id == user.id,
                UserSession.uuid == session_uuid,
                UserSession.revoked_at == None,  # noqa: E711
            )
        )
        user_session = result.scalar_one_or_none()

        if not user_session:
            return False

        user_session.revoked_at = now
        return True

    async def revoke_all_sessions(
        self, user: User, except_token_hash: str | None = None
    ) -> int:
        """Revoke all sessions for a user, optionally keeping one."""
        now = datetime.now(timezone.utc)
        result = await self.session.execute(
            select(UserSession).where(
                UserSession.user_id == user.id,
                UserSession.revoked_at == None,  # noqa: E711
            )
        )
        sessions = result.scalars().all()

        count = 0
        for s in sessions:
            if except_token_hash and s.refresh_token_hash == except_token_hash:
                continue
            s.revoked_at = now
            count += 1

        return count

    async def validate_session(self, refresh_token: str) -> UserSession | None:
        """Validate a session by refresh token."""
        token_hash = self._hash_token(refresh_token)
        now = datetime.now(timezone.utc)

        result = await self.session.execute(
            select(UserSession).where(
                UserSession.refresh_token_hash == token_hash,
                UserSession.expires_at > now,
                UserSession.revoked_at == None,  # noqa: E711
                UserSession.is_deleted == False,  # noqa: E712
            )
        )
        return result.scalar_one_or_none()

    async def update_session_activity(self, refresh_token: str) -> None:
        """Update last activity time for a session."""
        token_hash = self._hash_token(refresh_token)
        now = datetime.now(timezone.utc)

        result = await self.session.execute(
            select(UserSession).where(
                UserSession.refresh_token_hash == token_hash,
            )
        )
        user_session = result.scalar_one_or_none()
        if user_session:
            user_session.last_activity_at = now

    def _hash_token(self, token: str) -> str:
        """Hash a token for storage/lookup."""
        return hashlib.sha256(token.encode()).hexdigest()

    async def get_known_devices(self, user: User) -> list[KnownDevice]:
        """Get all known devices for a user."""
        result = await self.session.execute(
            select(KnownDevice)
            .where(
                KnownDevice.user_id == user.id,
                KnownDevice.is_deleted == False,  # noqa: E712
            )
            .order_by(KnownDevice.last_seen_at.desc())
        )
        return list(result.scalars().all())

    async def get_known_locations(self, user: User) -> list[KnownLocation]:
        """Get all known locations for a user."""
        result = await self.session.execute(
            select(KnownLocation)
            .where(
                KnownLocation.user_id == user.id,
                KnownLocation.is_deleted == False,  # noqa: E712
            )
            .order_by(KnownLocation.last_seen_at.desc())
        )
        return list(result.scalars().all())
