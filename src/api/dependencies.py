"""API dependencies for authentication and authorization."""

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_session
from src.core.security import decode_token
from src.models.user import User
from src.services.auth import AuthService

security = HTTPBearer()


@dataclass
class TokenPayload:
    """Decoded JWT token payload with user claims."""

    sub: str
    username: str
    token_version: int
    is_admin: bool
    roles: list[str]
    permissions: list[str]


def get_auth_service(session: AsyncSession = Depends(get_session)) -> AuthService:
    """Get authentication service instance."""
    return AuthService(session)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    auth_service: AuthService = Depends(get_auth_service),
) -> User:
    """Get current authenticated user from JWT token."""
    token = credentials.credentials
    payload = decode_token(token)

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_uuid = payload.get("sub")
    token_version = payload.get("token_version")

    user = await auth_service.get_user_by_uuid(user_uuid)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check token version (for logout-all-sessions)
    if user.token_version != token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check email verification
    if not await auth_service.has_verified_email(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification required",
        )

    return user


async def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        HTTPBearer(auto_error=False)
    ),
    auth_service: AuthService = Depends(get_auth_service),
) -> User | None:
    """Get current user if authenticated, None otherwise."""
    if not credentials:
        return None

    try:
        return await get_current_user(credentials, auth_service)
    except HTTPException:
        return None


async def get_current_admin_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Get current user and verify they are admin."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


async def get_token_payload(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> TokenPayload:
    """Extract and validate token payload from JWT."""
    token = credentials.credentials
    payload = decode_token(token)

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return TokenPayload(
        sub=payload.get("sub", ""),
        username=payload.get("username", ""),
        token_version=payload.get("token_version", 0),
        is_admin=payload.get("is_admin", False),
        roles=payload.get("roles", []),
        permissions=payload.get("permissions", []),
    )


class Authorize:
    """
    Flexible authorization dependency for protecting endpoints.

    Usage:
        # Admin only
        @router.get("/admin-only")
        async def admin_endpoint(user: User = Depends(Authorize())):
            ...

        # Require specific role
        @router.get("/editors")
        async def editors_endpoint(user: User = Depends(Authorize(roles=["editors"]))):
            ...

        # Require specific permission
        @router.get("/users")
        async def users_endpoint(user: User = Depends(Authorize(permissions=["users:read"]))):
            ...

        # Require any of the specified roles
        @router.get("/staff")
        async def staff_endpoint(user: User = Depends(Authorize(roles=["admin", "moderator"]))):
            ...

    Admin users bypass all role/permission checks.
    """

    def __init__(
        self,
        roles: list[str] | None = None,
        permissions: list[str] | None = None,
        require_all_roles: bool = False,
        require_all_permissions: bool = False,
    ):
        """
        Initialize authorization dependency.

        Args:
            roles: Required roles (user must have at least one, or all if require_all_roles=True)
            permissions: Required permissions (user must have at least one, or all if require_all_permissions=True)
            require_all_roles: If True, user must have ALL specified roles
            require_all_permissions: If True, user must have ALL specified permissions
        """
        self.roles = roles or []
        self.permissions = permissions or []
        self.require_all_roles = require_all_roles
        self.require_all_permissions = require_all_permissions

    async def __call__(
        self,
        token_payload: TokenPayload = Depends(get_token_payload),
        auth_service: AuthService = Depends(get_auth_service),
    ) -> User:
        """Validate authorization and return current user."""
        # Get user from database
        user = await auth_service.get_user_by_uuid(token_payload.sub)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check token version (for logout-all-sessions)
        if user.token_version != token_payload.token_version:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check email verification
        if not await auth_service.has_verified_email(user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email verification required",
            )

        # Admin bypasses all role/permission checks (check from DB, not token)
        if user.is_admin:
            return user

        # Only query roles/permissions if needed
        if self.roles or self.permissions:
            # Get current roles and permissions from database
            user_roles, user_permissions = await auth_service.get_user_roles_and_permissions(user)
            user_roles_set = set(user_roles)
            user_permissions_set = set(user_permissions)

            # Check roles if specified
            if self.roles:
                required_roles = set(self.roles)

                if self.require_all_roles:
                    if not required_roles.issubset(user_roles_set):
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Required roles: {', '.join(self.roles)}",
                        )
                else:
                    if not user_roles_set.intersection(required_roles):
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Required one of roles: {', '.join(self.roles)}",
                        )

            # Check permissions if specified
            if self.permissions:
                required_permissions = set(self.permissions)

                if self.require_all_permissions:
                    if not required_permissions.issubset(user_permissions_set):
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Required permissions: {', '.join(self.permissions)}",
                        )
                else:
                    if not user_permissions_set.intersection(required_permissions):
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Required one of permissions: {', '.join(self.permissions)}",
                        )

        return user


# Convenience type alias for common authorization patterns
CurrentUser = Annotated[User, Depends(get_current_user)]
AdminUser = Annotated[User, Depends(get_current_admin_user)]
