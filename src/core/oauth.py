"""OAuth provider configurations and utilities."""

from dataclasses import dataclass
from typing import Any

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client

from src.core.settings import get_settings

settings = get_settings()


@dataclass
class OAuthProvider:
    """OAuth provider configuration."""

    name: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scopes: list[str]


# Provider configurations
PROVIDERS: dict[str, OAuthProvider] = {
    "google": OAuthProvider(
        name="google",
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        userinfo_url="https://www.googleapis.com/oauth2/v3/userinfo",
        scopes=["openid", "email", "profile"],
    ),
    "microsoft": OAuthProvider(
        name="microsoft",
        authorize_url=f"https://login.microsoftonline.com/{settings.microsoft_tenant_id}/oauth2/v2.0/authorize",
        token_url=f"https://login.microsoftonline.com/{settings.microsoft_tenant_id}/oauth2/v2.0/token",
        userinfo_url="https://graph.microsoft.com/v1.0/me",
        scopes=["openid", "email", "profile", "User.Read"],
    ),
}


def get_provider(name: str) -> OAuthProvider | None:
    """Get OAuth provider configuration by name."""
    return PROVIDERS.get(name)


def get_available_providers() -> list[str]:
    """Get list of configured OAuth providers."""
    available = []
    if settings.google_client_id and settings.google_client_secret:
        available.append("google")
    if settings.microsoft_client_id and settings.microsoft_client_secret:
        available.append("microsoft")
    return available


def get_client_credentials(provider_name: str) -> tuple[str, str] | None:
    """Get client ID and secret for a provider."""
    if provider_name == "google":
        if settings.google_client_id and settings.google_client_secret:
            return settings.google_client_id, settings.google_client_secret
    elif provider_name == "microsoft":
        if settings.microsoft_client_id and settings.microsoft_client_secret:
            return settings.microsoft_client_id, settings.microsoft_client_secret
    return None


def create_oauth_client(provider_name: str) -> AsyncOAuth2Client | None:
    """Create an OAuth2 client for the specified provider."""
    provider = get_provider(provider_name)
    credentials = get_client_credentials(provider_name)

    if not provider or not credentials:
        return None

    client_id, client_secret = credentials

    return AsyncOAuth2Client(
        client_id=client_id,
        client_secret=client_secret,
        authorize_url=provider.authorize_url,
        token_endpoint=provider.token_url,
        redirect_uri=settings.oauth_redirect_uri,
    )


def get_authorization_url(provider_name: str, state: str) -> str | None:
    """Generate OAuth authorization URL for a provider."""
    provider = get_provider(provider_name)
    credentials = get_client_credentials(provider_name)

    if not provider or not credentials:
        return None

    client_id, _ = credentials

    params = {
        "client_id": client_id,
        "redirect_uri": settings.oauth_redirect_uri,
        "response_type": "code",
        "scope": " ".join(provider.scopes),
        "state": state,
    }

    # Add provider-specific params
    if provider_name == "google":
        params["access_type"] = "offline"
        params["prompt"] = "consent"

    query = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{provider.authorize_url}?{query}"


async def exchange_code_for_token(
    provider_name: str, code: str
) -> dict[str, Any] | None:
    """Exchange authorization code for access token."""
    provider = get_provider(provider_name)
    credentials = get_client_credentials(provider_name)

    if not provider or not credentials:
        return None

    client_id, client_secret = credentials

    async with httpx.AsyncClient() as client:
        response = await client.post(
            provider.token_url,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": settings.oauth_redirect_uri,
                "grant_type": "authorization_code",
            },
            headers={"Accept": "application/json"},
        )

        if response.status_code != 200:
            return None

        return response.json()


async def get_user_info(provider_name: str, access_token: str) -> dict[str, Any] | None:
    """Fetch user info from OAuth provider."""
    provider = get_provider(provider_name)

    if not provider:
        return None

    async with httpx.AsyncClient() as client:
        response = await client.get(
            provider.userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )

        if response.status_code != 200:
            return None

        return response.json()


def normalize_user_info(provider_name: str, raw_info: dict[str, Any]) -> dict[str, Any]:
    """Normalize user info from different providers to a common format."""
    if provider_name == "google":
        return {
            "provider": provider_name,
            "provider_user_id": raw_info.get("sub"),
            "email": raw_info.get("email"),
            "name": raw_info.get("name"),
            "picture": raw_info.get("picture"),
            "email_verified": raw_info.get("email_verified", False),
        }
    elif provider_name == "microsoft":
        return {
            "provider": provider_name,
            "provider_user_id": raw_info.get("id"),
            "email": raw_info.get("mail") or raw_info.get("userPrincipalName"),
            "name": raw_info.get("displayName"),
            "picture": None,  # Microsoft Graph requires separate call for photo
            "email_verified": True,  # Microsoft accounts have verified emails
        }

    return {
        "provider": provider_name,
        "provider_user_id": raw_info.get("id") or raw_info.get("sub"),
        "email": raw_info.get("email"),
        "name": raw_info.get("name"),
        "picture": raw_info.get("picture"),
        "email_verified": False,
    }
