"""Authentication service."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.geoip import GeoLocation
from src.core.request_context import RequestContext
from src.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_secure_token,
    hash_password,
    password_needs_rehash,
    verify_password,
)
from src.core.settings import get_settings
from src.core.totp import (
    generate_qr_code,
    generate_recovery_codes,
    generate_totp_secret,
    get_provisioning_uri,
    normalize_recovery_code,
    verify_totp_code,
)
from src.core.user_agent import DeviceInfo
from src.models.email import Email
from src.models.email_verification import EmailVerificationToken
from src.models.oauth_account import OAuthAccount
from src.models.oauth_state import OAuthState
from src.models.password_reset import PasswordResetToken
from src.models.recovery_code import RecoveryCode
from src.models.session import UserSession
from src.models.totp_pending import TOTPPendingAuth
from src.models.user import User

settings = get_settings()


class AuthService:
    """Authentication service handling all auth operations."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # === User Lookup Methods ===

    async def get_user_by_username(self, username: str) -> User | None:
        """Get user by username with emails loaded."""
        result = await self.session.execute(
            select(User)
            .options(selectinload(User.emails))
            .where(
                User.username == username,
                User.is_active == True,  # noqa: E712
                User.is_deleted == False,  # noqa: E712
            )
        )
        return result.scalar_one_or_none()

    async def get_user_by_email(self, email_address: str) -> User | None:
        """Get user by email address."""
        result = await self.session.execute(
            select(User)
            .join(Email)
            .options(selectinload(User.emails))
            .where(
                Email.email_address == email_address,
                User.is_active == True,  # noqa: E712
                User.is_deleted == False,  # noqa: E712
            )
        )
        return result.scalar_one_or_none()

    async def get_user_by_uuid(self, user_uuid: str) -> User | None:
        """Get user by UUID."""
        result = await self.session.execute(
            select(User)
            .options(selectinload(User.emails))
            .where(
                User.uuid == user_uuid,
                User.is_active == True,  # noqa: E712
                User.is_deleted == False,  # noqa: E712
            )
        )
        return result.scalar_one_or_none()

    async def get_primary_email(self, user: User) -> Email | None:
        """Get user's primary verified email."""
        for email in user.emails:
            if email.is_primary and email.is_verified:
                return email
        return None

    async def has_verified_email(self, user: User) -> bool:
        """Check if user has at least one verified email."""
        return any(email.is_verified for email in user.emails)

    # === Login Methods ===

    async def authenticate_user(self, login: str, password: str) -> User | None:
        """Authenticate user with username or email and password."""
        # Try username first, then email
        user = await self.get_user_by_username(login)
        if not user:
            user = await self.get_user_by_primary_email(login)

        if not user or not user.password:
            return None

        if not verify_password(password, user.password):
            return None

        # Rehash password if needed (algorithm parameters changed)
        if password_needs_rehash(user.password):
            user.password = hash_password(password)

        return user

    async def get_user_by_primary_email(self, email_address: str) -> User | None:
        """Get user by primary verified email address."""
        result = await self.session.execute(
            select(User)
            .join(Email)
            .options(selectinload(User.emails))
            .where(
                Email.email_address == email_address,
                Email.is_primary == True,  # noqa: E712
                Email.is_verified == True,  # noqa: E712
                User.is_active == True,  # noqa: E712
                User.is_deleted == False,  # noqa: E712
            )
        )
        return result.scalar_one_or_none()

    async def create_tokens(
        self,
        user: User,
        context: RequestContext | None = None,
    ) -> tuple[
        dict,
        bool,
        bool,
        UserSession | None,
        GeoLocation | None,
        DeviceInfo | None,
    ]:
        """
        Create access and refresh tokens for user.

        When context is provided, also creates a session and detects new device/location.

        Returns (tokens_dict, is_new_device, is_new_location, session, geo, device_info).
        """
        token_data = {
            "sub": str(user.uuid),
            "username": user.username,
            "token_version": user.token_version,
        }

        access_token = create_access_token(token_data)
        refresh_token = create_refresh_token(token_data)

        # Update last login
        user.last_login = datetime.now(timezone.utc)

        tokens = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.access_token_expire_minutes * 60,
        }

        # Create session if context provided
        is_new_device = False
        is_new_location = False
        session = None
        geo = None
        device_info = None

        if context:
            # Import here to avoid circular import
            from src.services.session import SessionService

            session_service = SessionService(self.session)
            (
                session,
                is_new_device,
                is_new_location,
                geo,
                device_info,
            ) = await session_service.create_session(user, refresh_token, context)

        return tokens, is_new_device, is_new_location, session, geo, device_info

    async def validate_refresh_token(self, refresh_token: str) -> User | None:
        """Validate refresh token and return user if valid."""
        payload = decode_token(refresh_token)
        if not payload:
            return None

        if payload.get("type") != "refresh":
            return None

        user_uuid = payload.get("sub")
        token_version = payload.get("token_version")

        user = await self.get_user_by_uuid(user_uuid)
        if not user:
            return None

        # Check token version (for logout-all-sessions)
        if user.token_version != token_version:
            return None

        return user

    # === Registration ===

    async def register_user(
        self,
        username: str,
        email_address: str,
        password: str,
    ) -> tuple[User, str]:
        """
        Register a new user.

        Returns (user, verification_token).
        """
        # Create user with hashed password
        user = User(
            username=username,
            password=hash_password(password),
            is_admin=False,
        )
        self.session.add(user)
        await self.session.flush()

        # Create email (unverified, primary)
        email = Email(
            user_id=user.id,
            email_address=email_address,
            is_primary=True,
            is_verified=False,
        )
        self.session.add(email)
        await self.session.flush()

        # Create verification token
        token = generate_secure_token()
        expires_at = datetime.now(timezone.utc) + timedelta(
            hours=settings.email_verification_expire_hours
        )
        verification = EmailVerificationToken(
            email_id=email.id,
            token=token,
            expires_at=expires_at,
        )
        self.session.add(verification)
        await self.session.flush()

        await self.session.refresh(user)
        return user, token

    # === Email Verification ===

    async def verify_email(self, token: str) -> bool:
        """Verify email address using token."""
        result = await self.session.execute(
            select(EmailVerificationToken).where(
                EmailVerificationToken.token == token,
                EmailVerificationToken.used_at == None,  # noqa: E711
                EmailVerificationToken.expires_at > datetime.now(timezone.utc),
            )
        )
        verification = result.scalar_one_or_none()

        if not verification:
            return False

        # Mark token as used
        verification.used_at = datetime.now(timezone.utc)

        # Mark email as verified
        email_result = await self.session.execute(
            select(Email).where(Email.id == verification.email_id)
        )
        email = email_result.scalar_one_or_none()
        if email:
            email.is_verified = True

        return True

    async def create_email_verification_token(self, email: Email) -> str:
        """Create a new email verification token."""
        token = generate_secure_token()
        expires_at = datetime.now(timezone.utc) + timedelta(
            hours=settings.email_verification_expire_hours
        )
        verification = EmailVerificationToken(
            email_id=email.id,
            token=token,
            expires_at=expires_at,
        )
        self.session.add(verification)
        await self.session.flush()
        return token

    async def get_unverified_primary_email(self, user: User) -> Email | None:
        """Get user's primary unverified email."""
        for email in user.emails:
            if email.is_primary and not email.is_verified:
                return email
        return None

    # === Magic Link ===

    async def create_magic_link(self, email_address: str) -> tuple[User, str] | None:
        """Create magic link token for email login."""
        user = await self.get_user_by_email(email_address)
        if not user:
            return None

        # Check user has verified email
        if not await self.has_verified_email(user):
            return None

        token = generate_secure_token()
        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=settings.magic_link_expire_minutes
        )

        user.magic_link_token = token
        user.magic_link_expires_at = expires_at

        return user, token

    async def verify_magic_link(self, token: str) -> User | None:
        """Verify magic link token and return user."""
        result = await self.session.execute(
            select(User)
            .options(selectinload(User.emails))
            .where(
                User.magic_link_token == token,
                User.magic_link_expires_at > datetime.now(timezone.utc),
                User.is_active == True,  # noqa: E712
                User.is_deleted == False,  # noqa: E712
            )
        )
        user = result.scalar_one_or_none()

        if user:
            # Clear magic link token after use
            user.magic_link_token = None
            user.magic_link_expires_at = None

        return user

    # === Password Reset ===

    async def create_password_reset_token(
        self, email_address: str
    ) -> tuple[User, str] | None:
        """Create password reset token."""
        user = await self.get_user_by_email(email_address)
        if not user:
            return None

        token = generate_secure_token()
        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=settings.password_reset_expire_minutes
        )

        reset_token = PasswordResetToken(
            user_id=user.id,
            token=token,
            expires_at=expires_at,
        )
        self.session.add(reset_token)
        await self.session.flush()

        return user, token

    async def reset_password(self, token: str, new_password: str) -> bool:
        """Reset password using token."""
        result = await self.session.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.token == token,
                PasswordResetToken.used_at == None,  # noqa: E711
                PasswordResetToken.expires_at > datetime.now(timezone.utc),
            )
        )
        reset_token = result.scalar_one_or_none()

        if not reset_token:
            return False

        # Mark token as used
        reset_token.used_at = datetime.now(timezone.utc)

        # Update user password
        user_result = await self.session.execute(
            select(User).where(User.id == reset_token.user_id)
        )
        user = user_result.scalar_one_or_none()
        if not user:
            return False

        user.password = hash_password(new_password)
        # Invalidate all existing sessions
        user.token_version += 1

        return True

    # === Password Change (Authenticated) ===

    async def change_password(
        self,
        user: User,
        current_password: str,
        new_password: str,
    ) -> bool:
        """Change password for authenticated user."""
        if not user.password:
            return False

        if not verify_password(current_password, user.password):
            return False

        user.password = hash_password(new_password)
        # Invalidate all existing sessions
        user.token_version += 1

        return True

    # === Logout ===

    async def logout_all_sessions(self, user: User) -> None:
        """Invalidate all sessions by incrementing token version."""
        user.token_version += 1

    # === OAuth ===

    async def create_oauth_state(
        self, provider: str, redirect_uri: str | None = None
    ) -> str:
        """Create and store OAuth state token."""
        state = generate_secure_token()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=settings.oauth_state_expire_minutes)

        oauth_state = OAuthState(
            state=state,
            provider=provider,
            redirect_uri=redirect_uri,
            created_at=now,
            expires_at=expires_at,
        )
        self.session.add(oauth_state)
        await self.session.flush()

        return state

    async def validate_oauth_state(self, state: str) -> OAuthState | None:
        """Validate and consume OAuth state token."""
        result = await self.session.execute(
            select(OAuthState).where(
                OAuthState.state == state,
                OAuthState.used_at == None,  # noqa: E711
                OAuthState.expires_at > datetime.now(timezone.utc),
            )
        )
        oauth_state = result.scalar_one_or_none()

        if oauth_state:
            # Mark as used
            oauth_state.used_at = datetime.now(timezone.utc)

        return oauth_state

    async def get_oauth_account(
        self, provider: str, provider_user_id: str
    ) -> OAuthAccount | None:
        """Get OAuth account by provider and provider user ID."""
        result = await self.session.execute(
            select(OAuthAccount).where(
                OAuthAccount.provider == provider,
                OAuthAccount.provider_user_id == provider_user_id,
                OAuthAccount.is_deleted == False,  # noqa: E712
            )
        )
        return result.scalar_one_or_none()

    async def get_or_create_oauth_user(
        self,
        provider: str,
        provider_user_id: str,
        email: str | None,
        name: str | None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        expires_at: datetime | None = None,
    ) -> tuple[User, bool]:
        """
        Find existing user by OAuth account or email, or create new user.

        Returns (user, is_new_user).
        """
        # First, check if OAuth account already exists
        oauth_account = await self.get_oauth_account(provider, provider_user_id)
        if oauth_account:
            # Get existing user
            result = await self.session.execute(
                select(User)
                .options(selectinload(User.emails))
                .where(User.id == oauth_account.user_id)
            )
            user = result.scalar_one_or_none()
            if user:
                # Update OAuth tokens
                oauth_account.access_token = access_token
                oauth_account.refresh_token = refresh_token
                oauth_account.expires_at = expires_at
                return user, False

        # Check if user exists with this email
        if email:
            existing_user = await self.get_user_by_email(email)
            if existing_user:
                # Link OAuth account to existing user
                await self.link_oauth_account(
                    existing_user,
                    provider,
                    provider_user_id,
                    access_token,
                    refresh_token,
                    expires_at,
                )
                return existing_user, False

        # Create new user
        username = self._generate_username(name, email, provider, provider_user_id)
        user = User(
            username=username,
            password=None,  # OAuth users don't have password
            is_admin=False,
        )
        self.session.add(user)
        await self.session.flush()

        # Create verified email if provided
        if email:
            email_obj = Email(
                user_id=user.id,
                email_address=email,
                is_primary=True,
                is_verified=True,  # OAuth emails are pre-verified
            )
            self.session.add(email_obj)
            await self.session.flush()

        # Link OAuth account
        await self.link_oauth_account(
            user,
            provider,
            provider_user_id,
            access_token,
            refresh_token,
            expires_at,
        )

        await self.session.refresh(user)
        return user, True

    async def link_oauth_account(
        self,
        user: User,
        provider: str,
        provider_user_id: str,
        access_token: str | None = None,
        refresh_token: str | None = None,
        expires_at: datetime | None = None,
    ) -> OAuthAccount:
        """Link OAuth account to existing user."""
        oauth_account = OAuthAccount(
            user_id=user.id,
            provider=provider,
            provider_user_id=provider_user_id,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at,
        )
        self.session.add(oauth_account)
        await self.session.flush()
        return oauth_account

    def _generate_username(
        self,
        name: str | None,
        email: str | None,
        provider: str,
        provider_user_id: str,
    ) -> str:
        """Generate a username for OAuth user."""
        if name:
            # Clean name: lowercase, replace spaces with underscores
            base = name.lower().replace(" ", "_")
            # Remove non-alphanumeric chars except underscore
            base = "".join(c for c in base if c.isalnum() or c == "_")
            if len(base) >= 3:
                return f"{base}_{provider_user_id[:8]}"

        if email:
            # Use email prefix
            base = email.split("@")[0].lower()
            base = "".join(c for c in base if c.isalnum() or c == "_")
            if len(base) >= 3:
                return f"{base}_{provider_user_id[:8]}"

        # Fallback to provider + ID
        return f"{provider}_{provider_user_id[:16]}"

    # === TOTP ===

    def setup_totp(self, user: User) -> tuple[str, str, str]:
        """
        Generate TOTP secret and provisioning info for setup.

        Returns (secret, provisioning_uri, qr_code_base64).
        """
        secret = generate_totp_secret()
        # Store secret temporarily (not enabled yet)
        user.totp_secret = secret

        provisioning_uri = get_provisioning_uri(secret, user.username)
        qr_code = generate_qr_code(provisioning_uri)

        return secret, provisioning_uri, qr_code

    def verify_and_enable_totp(self, user: User, code: str) -> bool:
        """Verify TOTP code and enable TOTP for user."""
        if not user.totp_secret:
            return False

        if not verify_totp_code(user.totp_secret, code):
            return False

        user.totp_enabled = True
        return True

    async def disable_totp(
        self, user: User, password: str, code: str
    ) -> bool:
        """Disable TOTP (requires password and current code)."""
        if not user.totp_enabled or not user.totp_secret:
            return False

        # Verify password
        if not user.password or not verify_password(password, user.password):
            return False

        # Verify TOTP code
        if not verify_totp_code(user.totp_secret, code):
            return False

        # Disable TOTP
        user.totp_enabled = False
        user.totp_secret = None

        # Delete all recovery codes
        await self.session.execute(
            select(RecoveryCode)
            .where(RecoveryCode.user_id == user.id)
        )
        from sqlalchemy import delete
        await self.session.execute(
            delete(RecoveryCode).where(RecoveryCode.user_id == user.id)
        )

        return True

    def verify_totp(self, user: User, code: str) -> bool:
        """Verify TOTP code for user."""
        if not user.totp_enabled or not user.totp_secret:
            return False

        return verify_totp_code(user.totp_secret, code)

    async def create_totp_pending_auth(self, user: User) -> str:
        """Create a pending TOTP auth token for login flow."""
        token = generate_secure_token()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=5)

        pending = TOTPPendingAuth(
            user_id=user.id,
            token=token,
            created_at=now,
            expires_at=expires_at,
        )
        self.session.add(pending)
        await self.session.flush()

        return token

    async def validate_totp_pending_auth(self, token: str) -> User | None:
        """Validate and consume TOTP pending auth token."""
        result = await self.session.execute(
            select(TOTPPendingAuth).where(
                TOTPPendingAuth.token == token,
                TOTPPendingAuth.used_at == None,  # noqa: E711
                TOTPPendingAuth.expires_at > datetime.now(timezone.utc),
            )
        )
        pending = result.scalar_one_or_none()

        if not pending:
            return None

        # Mark as used
        pending.used_at = datetime.now(timezone.utc)

        # Get user
        user = await self.get_user_by_id(pending.user_id)
        return user

    async def get_user_by_id(self, user_id: int) -> User | None:
        """Get user by ID."""
        result = await self.session.execute(
            select(User)
            .options(selectinload(User.emails))
            .where(
                User.id == user_id,
                User.is_active == True,  # noqa: E712
                User.is_deleted == False,  # noqa: E712
            )
        )
        return result.scalar_one_or_none()

    # === Recovery Codes ===

    async def create_recovery_codes(self, user: User) -> list[str]:
        """Generate new recovery codes (invalidates old ones)."""
        # Delete existing recovery codes
        from sqlalchemy import delete
        await self.session.execute(
            delete(RecoveryCode).where(RecoveryCode.user_id == user.id)
        )

        # Generate new codes
        codes = generate_recovery_codes()

        # Store hashed codes
        for code in codes:
            normalized = normalize_recovery_code(code)
            code_hash = hash_password(normalized)
            recovery = RecoveryCode(
                user_id=user.id,
                code_hash=code_hash,
            )
            self.session.add(recovery)

        await self.session.flush()

        return codes

    async def verify_recovery_code(self, user: User, code: str) -> bool:
        """Verify and consume a recovery code."""
        normalized = normalize_recovery_code(code)

        # Get all unused recovery codes for user
        result = await self.session.execute(
            select(RecoveryCode).where(
                RecoveryCode.user_id == user.id,
                RecoveryCode.used_at == None,  # noqa: E711
            )
        )
        recovery_codes = result.scalars().all()

        # Check each code
        for recovery in recovery_codes:
            if verify_password(normalized, recovery.code_hash):
                # Mark as used
                recovery.used_at = datetime.now(timezone.utc)
                return True

        return False

    async def get_recovery_codes_count(self, user: User) -> int:
        """Get count of remaining unused recovery codes."""
        result = await self.session.execute(
            select(RecoveryCode).where(
                RecoveryCode.user_id == user.id,
                RecoveryCode.used_at == None,  # noqa: E711
            )
        )
        return len(result.scalars().all())
