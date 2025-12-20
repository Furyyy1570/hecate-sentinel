"""OAuth schemas."""

from src.schemas.base import BaseSchema


class OAuthProviderInfo(BaseSchema):
    """OAuth provider information."""

    name: str
    enabled: bool


class OAuthProvidersResponse(BaseSchema):
    """List of available OAuth providers."""

    providers: list[OAuthProviderInfo]


class OAuthAuthorizeResponse(BaseSchema):
    """Response with OAuth authorization URL."""

    authorization_url: str
    state: str
    provider: str


class OAuthCallbackResponse(BaseSchema):
    """Response after successful OAuth callback."""

    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    is_new_user: bool


class OAuthUserInfo(BaseSchema):
    """Normalized user info from OAuth provider."""

    provider: str
    provider_user_id: str
    email: str | None
    name: str | None
    picture: str | None
    email_verified: bool
