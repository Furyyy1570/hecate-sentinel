"""Authentication API routes."""

from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_auth_service, get_current_user
from src.core.database import get_session
from src.core.email_sender import email_sender
from src.core.request_context import get_request_context
from src.core.settings import get_settings
from src.core.user_agent import get_device_friendly_name
from src.models.audit_log import AuditEventType
from src.models.user import User
from src.services.audit import AuditService
from src.core.oauth import (
    exchange_code_for_token,
    get_authorization_url,
    get_available_providers,
    get_provider,
    get_user_info,
    normalize_user_info,
)
from src.schemas.auth import (
    AuthUserResponse,
    ChangePasswordRequest,
    EmailVerifyRequest,
    LoginRequest,
    LoginResponse,
    MagicLinkRequest,
    MagicLinkVerifyRequest,
    MessageResponse,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    RefreshTokenRequest,
    RegisterRequest,
    TokenResponse,
)
from src.schemas.totp import (
    RecoveryCodeVerifyRequest,
    RecoveryCodesResponse,
    TOTPDisableRequest,
    TOTPEnableRequest,
    TOTPSetupResponse,
    TOTPStatusResponse,
    TOTPVerifyRequest,
)
from src.schemas.oauth import (
    OAuthAuthorizeResponse,
    OAuthCallbackResponse,
    OAuthProviderInfo,
    OAuthProvidersResponse,
)
from src.services.auth import AuthService
from src.services.api_key import APIKeyService
from src.schemas.introspect import (
    IntrospectRequest,
    IntrospectResponse,
    ServiceAPIKeyCreate,
    ServiceAPIKeyResponse,
    ServiceAPIKeyInfo,
)

settings = get_settings()
router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login", response_model=LoginResponse)
async def login(
    data: LoginRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> LoginResponse:
    """
    Authenticate user with username or email and password.

    Returns JWT access and refresh tokens, or if TOTP is enabled,
    returns a temporary token for TOTP verification.
    User must have a verified email to log in.
    """
    context = get_request_context(request)
    audit_service = AuditService(session)

    user = await auth_service.authenticate_user(data.login, data.password)

    if not user:
        # Log failed attempt - try to find user for logging
        potential_user = await auth_service.get_user_by_username(data.login)
        if not potential_user:
            potential_user = await auth_service.get_user_by_primary_email(data.login)

        await audit_service.log_event(
            event_type=AuditEventType.LOGIN_FAILED,
            user=potential_user,
            context=context,
            success=False,
            failure_reason="Invalid credentials",
        )
        await session.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Check email verification
    if not await auth_service.has_verified_email(user):
        await audit_service.log_event(
            event_type=AuditEventType.LOGIN_FAILED,
            user=user,
            context=context,
            success=False,
            failure_reason="Email not verified",
        )
        await session.commit()

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification required before login",
        )

    # Check if TOTP is enabled
    if user.totp_enabled:
        totp_token = await auth_service.create_totp_pending_auth(user)
        await session.commit()
        return LoginResponse(requires_totp=True, totp_token=totp_token)

    # Create tokens with session tracking
    (
        tokens,
        is_new_device,
        is_new_location,
        user_session,
        geo,
        device_info,
    ) = await auth_service.create_tokens(user, context)

    # Log successful login
    await audit_service.log_event(
        event_type=AuditEventType.LOGIN_SUCCESS,
        user=user,
        context=context,
        session_id=user_session.id if user_session else None,
        country=geo.country if geo else None,
        city=geo.city if geo else None,
    )

    await session.commit()

    # Send new device/location alerts in background
    primary_email = await auth_service.get_primary_email(user)
    if primary_email:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        if is_new_device and device_info:
            device_name = get_device_friendly_name(device_info)
            background_tasks.add_task(
                email_sender.send_new_device_alert,
                primary_email.email_address,
                device_name,
                context.ip_address,
                timestamp,
            )
        if is_new_location and geo:
            location = f"{geo.city or 'Unknown'}, {geo.country or 'Unknown'}"
            background_tasks.add_task(
                email_sender.send_new_location_alert,
                primary_email.email_address,
                location,
                context.ip_address,
                geo.isp,
                timestamp,
            )

    return LoginResponse(**tokens)


@router.post(
    "/register", response_model=MessageResponse, status_code=status.HTTP_201_CREATED
)
async def register(
    data: RegisterRequest,
    background_tasks: BackgroundTasks,
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """
    Register a new user account.

    Registration can be disabled via ALLOW_REGISTRATION setting.
    A verification email will be sent to confirm the email address.
    """
    if not settings.allow_registration:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration is disabled",
        )

    # Check if username exists
    existing_user = await auth_service.get_user_by_username(data.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )

    # Check if email exists
    existing_email = await auth_service.get_user_by_email(data.email)
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email address already registered",
        )

    user, verification_token = await auth_service.register_user(
        username=data.username,
        email_address=data.email,
        password=data.password,
    )
    await session.commit()

    # Send verification email in background
    background_tasks.add_task(
        email_sender.send_verification_email,
        data.email,
        verification_token,
    )

    return MessageResponse(
        message="Registration successful. Please check your email to verify your account."
    )


@router.post("/verify-email", response_model=MessageResponse)
async def verify_email(
    data: EmailVerifyRequest,
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Verify email address using the token sent via email."""
    success = await auth_service.verify_email(data.token)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        )

    await session.commit()
    return MessageResponse(message="Email verified successfully")


@router.post("/resend-verification", response_model=MessageResponse)
async def resend_verification(
    data: MagicLinkRequest,  # Reusing schema - just needs email
    background_tasks: BackgroundTasks,
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Resend email verification link."""
    user = await auth_service.get_user_by_email(data.email)

    # Always return success to prevent email enumeration
    if user:
        primary_email = await auth_service.get_unverified_primary_email(user)
        if primary_email:
            token = await auth_service.create_email_verification_token(primary_email)
            await session.commit()
            background_tasks.add_task(
                email_sender.send_verification_email,
                data.email,
                token,
            )

    return MessageResponse(
        message="If an unverified account exists with this email, a verification link has been sent."
    )


@router.post("/magic-link/request", response_model=MessageResponse)
async def request_magic_link(
    data: MagicLinkRequest,
    background_tasks: BackgroundTasks,
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """
    Request a magic link for passwordless login.

    The magic link will be sent to the user's verified email address.
    """
    result = await auth_service.create_magic_link(data.email)

    # Always return success to prevent email enumeration
    if result:
        user, token = result
        await session.commit()
        background_tasks.add_task(
            email_sender.send_magic_link_email,
            data.email,
            token,
        )

    return MessageResponse(
        message="If a verified account exists with this email, a login link has been sent."
    )


@router.post("/magic-link/verify", response_model=TokenResponse)
async def verify_magic_link(
    data: MagicLinkVerifyRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """Verify magic link token and return JWT tokens."""
    context = get_request_context(request)
    audit_service = AuditService(session)

    user = await auth_service.verify_magic_link(data.token)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired magic link",
        )

    # Create tokens with session tracking
    (
        tokens,
        is_new_device,
        is_new_location,
        user_session,
        geo,
        device_info,
    ) = await auth_service.create_tokens(user, context)

    # Log successful login
    await audit_service.log_event(
        event_type=AuditEventType.LOGIN_SUCCESS,
        user=user,
        context=context,
        session_id=user_session.id if user_session else None,
        country=geo.country if geo else None,
        city=geo.city if geo else None,
        event_data={"method": "magic_link"},
    )

    await session.commit()

    # Send new device/location alerts in background
    primary_email = await auth_service.get_primary_email(user)
    if primary_email:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        if is_new_device and device_info:
            device_name = get_device_friendly_name(device_info)
            background_tasks.add_task(
                email_sender.send_new_device_alert,
                primary_email.email_address,
                device_name,
                context.ip_address,
                timestamp,
            )
        if is_new_location and geo:
            location = f"{geo.city or 'Unknown'}, {geo.country or 'Unknown'}"
            background_tasks.add_task(
                email_sender.send_new_location_alert,
                primary_email.email_address,
                location,
                context.ip_address,
                geo.isp,
                timestamp,
            )

    return TokenResponse(**tokens)


@router.post("/password-reset/request", response_model=MessageResponse)
async def request_password_reset(
    data: PasswordResetRequest,
    background_tasks: BackgroundTasks,
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """
    Request password reset link.

    The reset link will be sent to the user's email address.
    """
    result = await auth_service.create_password_reset_token(data.email)

    # Always return success to prevent email enumeration
    if result:
        user, token = result
        await session.commit()
        background_tasks.add_task(
            email_sender.send_password_reset_email,
            data.email,
            token,
        )

    return MessageResponse(
        message="If an account exists with this email, a password reset link has been sent."
    )


@router.post("/password-reset/confirm", response_model=MessageResponse)
async def confirm_password_reset(
    data: PasswordResetConfirmRequest,
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Reset password using the token sent via email."""
    success = await auth_service.reset_password(data.token, data.new_password)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    await session.commit()
    return MessageResponse(message="Password reset successfully")


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    data: RefreshTokenRequest,
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """Get new access token using refresh token."""
    user = await auth_service.validate_refresh_token(data.refresh_token)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    tokens, _, _, _, _, _ = await auth_service.create_tokens(user)
    await session.commit()

    return TokenResponse(**tokens)


@router.post("/change-password", response_model=MessageResponse)
async def change_password(
    data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Change password for authenticated user."""
    success = await auth_service.change_password(
        current_user,
        data.current_password,
        data.new_password,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    await session.commit()
    return MessageResponse(
        message="Password changed successfully. All other sessions have been logged out."
    )


@router.post("/logout-all", response_model=MessageResponse)
async def logout_all_sessions(
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Log out from all devices by invalidating all tokens."""
    await auth_service.logout_all_sessions(current_user)
    await session.commit()

    return MessageResponse(message="All sessions have been logged out")


@router.get("/me", response_model=AuthUserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> AuthUserResponse:
    """Get current authenticated user information."""
    primary_email = await auth_service.get_primary_email(current_user)

    return AuthUserResponse(
        uuid=str(current_user.uuid),
        username=current_user.username,
        email=primary_email.email_address if primary_email else None,
        is_admin=current_user.is_admin,
        email_verified=await auth_service.has_verified_email(current_user),
    )


# === OAuth Endpoints ===


@router.get("/oauth/providers", response_model=OAuthProvidersResponse)
async def list_oauth_providers() -> OAuthProvidersResponse:
    """List available OAuth providers."""
    available = get_available_providers()
    providers = [
        OAuthProviderInfo(name=name, enabled=name in available)
        for name in ["google", "microsoft"]
    ]
    return OAuthProvidersResponse(providers=providers)


@router.get("/oauth/{provider}/authorize", response_model=OAuthAuthorizeResponse)
async def oauth_authorize(
    provider: str,
    redirect_uri: str | None = None,
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> OAuthAuthorizeResponse:
    """
    Get OAuth authorization URL for a provider.

    The frontend should redirect the user to the returned URL.
    """
    # Validate provider
    if not get_provider(provider):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown OAuth provider: {provider}",
        )

    if provider not in get_available_providers():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth provider not configured: {provider}",
        )

    # Create state token
    state = await auth_service.create_oauth_state(provider, redirect_uri)
    await session.commit()

    # Generate authorization URL
    authorization_url = get_authorization_url(provider, state)
    if not authorization_url:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate authorization URL",
        )

    return OAuthAuthorizeResponse(
        authorization_url=authorization_url,
        state=state,
        provider=provider,
    )


@router.get("/oauth/callback", response_model=OAuthCallbackResponse)
async def oauth_callback(
    code: str,
    state: str,
    request: Request,
    background_tasks: BackgroundTasks,
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> OAuthCallbackResponse:
    """
    Handle OAuth callback from provider.

    Exchanges authorization code for tokens and creates/links user account.
    """
    context = get_request_context(request)
    audit_service = AuditService(session)

    # Validate state
    oauth_state = await auth_service.validate_oauth_state(state)
    if not oauth_state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OAuth state",
        )

    provider = oauth_state.provider

    # Exchange code for tokens
    token_response = await exchange_code_for_token(provider, code)
    if not token_response:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to exchange authorization code",
        )

    access_token = token_response.get("access_token")
    refresh_token = token_response.get("refresh_token")
    expires_in = token_response.get("expires_in")

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No access token in response",
        )

    # Calculate token expiration
    from datetime import timedelta

    expires_at = None
    if expires_in:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

    # Get user info from provider
    raw_user_info = await get_user_info(provider, access_token)
    if not raw_user_info:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to fetch user info from provider",
        )

    user_info = normalize_user_info(provider, raw_user_info)

    if not user_info.get("provider_user_id"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provider did not return user ID",
        )

    # Get or create user
    user, is_new_user = await auth_service.get_or_create_oauth_user(
        provider=provider,
        provider_user_id=user_info["provider_user_id"],
        email=user_info.get("email"),
        name=user_info.get("name"),
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
    )

    # Create JWT tokens with session tracking
    (
        tokens,
        is_new_device,
        is_new_location,
        user_session,
        geo,
        device_info,
    ) = await auth_service.create_tokens(user, context)

    # Log OAuth login
    await audit_service.log_event(
        event_type=AuditEventType.OAUTH_LOGIN,
        user=user,
        context=context,
        session_id=user_session.id if user_session else None,
        country=geo.country if geo else None,
        city=geo.city if geo else None,
        event_data={"provider": provider, "is_new_user": is_new_user},
    )

    await session.commit()

    # Send new device/location alerts in background
    primary_email = await auth_service.get_primary_email(user)
    if primary_email:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        if is_new_device and device_info:
            device_name = get_device_friendly_name(device_info)
            background_tasks.add_task(
                email_sender.send_new_device_alert,
                primary_email.email_address,
                device_name,
                context.ip_address,
                timestamp,
            )
        if is_new_location and geo:
            location = f"{geo.city or 'Unknown'}, {geo.country or 'Unknown'}"
            background_tasks.add_task(
                email_sender.send_new_location_alert,
                primary_email.email_address,
                location,
                context.ip_address,
                geo.isp,
                timestamp,
            )

    return OAuthCallbackResponse(
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_type=tokens["token_type"],
        expires_in=tokens["expires_in"],
        is_new_user=is_new_user,
    )


# === TOTP Endpoints ===


@router.get("/totp/status", response_model=TOTPStatusResponse)
async def get_totp_status(
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> TOTPStatusResponse:
    """Get TOTP status for the current user."""
    recovery_count = await auth_service.get_recovery_codes_count(current_user)
    return TOTPStatusResponse(
        enabled=current_user.totp_enabled,
        recovery_codes_remaining=recovery_count,
    )


@router.post("/totp/setup", response_model=TOTPSetupResponse)
async def setup_totp(
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> TOTPSetupResponse:
    """
    Start TOTP setup process.

    Returns the secret, provisioning URI, and QR code.
    User must confirm setup with /totp/enable endpoint.
    """
    if current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP is already enabled",
        )

    secret, provisioning_uri, qr_code = await auth_service.setup_totp(current_user)
    await session.commit()

    return TOTPSetupResponse(
        secret=secret,
        provisioning_uri=provisioning_uri,
        qr_code=qr_code,
    )


@router.post("/totp/enable", response_model=RecoveryCodesResponse)
async def enable_totp(
    data: TOTPEnableRequest,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> RecoveryCodesResponse:
    """
    Enable TOTP by verifying the code from authenticator app.

    Returns recovery codes (save these, they are only shown once).
    """
    if current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP is already enabled",
        )

    if not current_user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP setup not started. Call /totp/setup first.",
        )

    success = await auth_service.verify_and_enable_totp(current_user, data.code)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code",
        )

    # Generate recovery codes
    codes = await auth_service.create_recovery_codes(current_user)
    await session.commit()

    return RecoveryCodesResponse(codes=codes)


@router.post("/totp/disable", response_model=MessageResponse)
async def disable_totp(
    data: TOTPDisableRequest,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """
    Disable TOTP for the current user.

    Requires password and current TOTP code for verification.
    """
    if not current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP is not enabled",
        )

    success = await auth_service.disable_totp(current_user, data.password, data.code)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password or TOTP code",
        )

    await session.commit()
    return MessageResponse(message="TOTP has been disabled")


@router.post("/totp/verify", response_model=TokenResponse)
async def verify_totp(
    data: TOTPVerifyRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """
    Verify TOTP code during login.

    Use the totp_token from the login response along with
    the code from your authenticator app.
    """
    context = get_request_context(request)
    audit_service = AuditService(session)

    user = await auth_service.validate_totp_pending_auth(data.totp_token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired TOTP token",
        )

    if not await auth_service.verify_totp(user, data.code):
        await audit_service.log_event(
            event_type=AuditEventType.TOTP_FAILED,
            user=user,
            context=context,
            success=False,
            failure_reason="Invalid TOTP code",
        )
        await session.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP code",
        )

    # Create tokens with session tracking
    (
        tokens,
        is_new_device,
        is_new_location,
        user_session,
        geo,
        device_info,
    ) = await auth_service.create_tokens(user, context)

    # Log successful TOTP verification and login
    await audit_service.log_event(
        event_type=AuditEventType.TOTP_VERIFIED,
        user=user,
        context=context,
        session_id=user_session.id if user_session else None,
        country=geo.country if geo else None,
        city=geo.city if geo else None,
    )

    await session.commit()

    # Send new device/location alerts in background
    primary_email = await auth_service.get_primary_email(user)
    if primary_email:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        if is_new_device and device_info:
            device_name = get_device_friendly_name(device_info)
            background_tasks.add_task(
                email_sender.send_new_device_alert,
                primary_email.email_address,
                device_name,
                context.ip_address,
                timestamp,
            )
        if is_new_location and geo:
            location = f"{geo.city or 'Unknown'}, {geo.country or 'Unknown'}"
            background_tasks.add_task(
                email_sender.send_new_location_alert,
                primary_email.email_address,
                location,
                context.ip_address,
                geo.isp,
                timestamp,
            )

    return TokenResponse(**tokens)


@router.post("/totp/recover", response_model=TokenResponse)
async def verify_recovery_code(
    data: RecoveryCodeVerifyRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """
    Login using a recovery code when TOTP device is unavailable.

    Use the totp_token from the login response along with
    one of your recovery codes.
    """
    context = get_request_context(request)
    audit_service = AuditService(session)

    user = await auth_service.validate_totp_pending_auth(data.totp_token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired TOTP token",
        )

    success = await auth_service.verify_recovery_code(user, data.code)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid recovery code",
        )

    # Log recovery code usage
    await audit_service.log_event(
        event_type=AuditEventType.RECOVERY_CODE_USED,
        user=user,
        context=context,
    )

    # Create tokens with session tracking
    (
        tokens,
        is_new_device,
        is_new_location,
        user_session,
        geo,
        device_info,
    ) = await auth_service.create_tokens(user, context)

    # Log successful login
    await audit_service.log_event(
        event_type=AuditEventType.LOGIN_SUCCESS,
        user=user,
        context=context,
        session_id=user_session.id if user_session else None,
        country=geo.country if geo else None,
        city=geo.city if geo else None,
        event_data={"method": "recovery_code"},
    )

    await session.commit()

    # Send new device/location alerts in background
    primary_email = await auth_service.get_primary_email(user)
    if primary_email:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        if is_new_device and device_info:
            device_name = get_device_friendly_name(device_info)
            background_tasks.add_task(
                email_sender.send_new_device_alert,
                primary_email.email_address,
                device_name,
                context.ip_address,
                timestamp,
            )
        if is_new_location and geo:
            location = f"{geo.city or 'Unknown'}, {geo.country or 'Unknown'}"
            background_tasks.add_task(
                email_sender.send_new_location_alert,
                primary_email.email_address,
                location,
                context.ip_address,
                geo.isp,
                timestamp,
            )

    return TokenResponse(**tokens)


@router.post("/totp/recovery-codes", response_model=RecoveryCodesResponse)
async def regenerate_recovery_codes(
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> RecoveryCodesResponse:
    """
    Generate new recovery codes.

    This invalidates all previous recovery codes.
    Requires TOTP to be enabled.
    """
    if not current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP is not enabled",
        )

    codes = await auth_service.create_recovery_codes(current_user)
    await session.commit()

    return RecoveryCodesResponse(codes=codes)


# === Token Introspection ===


@router.post("/introspect", response_model=IntrospectResponse)
async def introspect_token(
    data: IntrospectRequest,
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
    session: AsyncSession = Depends(get_session),
) -> IntrospectResponse:
    """
    Validate a JWT token and return user information.

    This endpoint is for service-to-service authentication.
    Requires a valid service API key in the Authorization header.

    Usage:
        POST /auth/introspect
        Authorization: Bearer <service-api-key>
        Body: { "token": "<user-jwt-token>" }
    """
    # Extract service API key from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    service_api_key = auth_header.split(" ", 1)[1]

    # Validate service API key
    api_key_service = APIKeyService(session)
    api_key_record = await api_key_service.validate_api_key(service_api_key)

    if not api_key_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid service API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Now validate the user token
    from src.core.security import decode_token

    payload = decode_token(data.token)

    if not payload:
        await session.commit()  # Save last_used_at update
        return IntrospectResponse(valid=False)

    if payload.get("type") != "access":
        await session.commit()
        return IntrospectResponse(valid=False)

    user_uuid = payload.get("sub")
    token_version = payload.get("token_version")

    # Get user from database
    user = await auth_service.get_user_by_uuid(user_uuid)

    if not user:
        await session.commit()
        return IntrospectResponse(valid=False)

    # Check token version (for logout-all-sessions)
    if user.token_version != token_version:
        await session.commit()
        return IntrospectResponse(valid=False)

    # Check email verification
    if not await auth_service.has_verified_email(user):
        await session.commit()
        return IntrospectResponse(valid=False)

    # Get roles and permissions from database (real-time)
    roles, permissions = await auth_service.get_user_roles_and_permissions(user)

    await session.commit()

    return IntrospectResponse(
        valid=True,
        user_id=user.uuid,
        username=user.username,
        is_admin=user.is_admin,
        roles=roles,
        permissions=permissions,
    )


# === Service API Key Management ===


@router.post("/service-keys", response_model=ServiceAPIKeyResponse)
async def create_service_api_key(
    data: ServiceAPIKeyCreate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ServiceAPIKeyResponse:
    """
    Create a new service API key.

    Admin only. The API key is only shown once upon creation.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    api_key_service = APIKeyService(session)

    # Check if name already exists
    existing = await api_key_service.get_api_key_by_name(data.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Service name already exists",
        )

    record, api_key = await api_key_service.create_api_key(
        name=data.name,
        description=data.description,
    )
    await session.commit()

    return ServiceAPIKeyResponse(
        name=record.name,
        key_prefix=record.key_prefix,
        api_key=api_key,
    )


@router.get("/service-keys", response_model=list[ServiceAPIKeyInfo])
async def list_service_api_keys(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[ServiceAPIKeyInfo]:
    """
    List all service API keys.

    Admin only. Does not show the actual keys.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    api_key_service = APIKeyService(session)
    records = await api_key_service.list_api_keys()

    return [
        ServiceAPIKeyInfo(
            uuid=record.uuid,
            name=record.name,
            description=record.description,
            key_prefix=record.key_prefix,
            is_active=record.is_active,
        )
        for record in records
    ]


@router.delete("/service-keys/{name}", response_model=MessageResponse)
async def revoke_service_api_key(
    name: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """
    Revoke a service API key.

    Admin only.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    api_key_service = APIKeyService(session)
    success = await api_key_service.revoke_api_key(name)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Service API key not found",
        )

    await session.commit()
    return MessageResponse(message=f"Service API key '{name}' has been revoked")
