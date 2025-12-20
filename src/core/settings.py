"""Application settings."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    app_name: str = "Hecate Sentinel"
    debug: bool = False
    environment: str = "development"
    log_level: str = "INFO"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # Database
    db_host: str = "localhost"
    db_port: int = 5432
    db_user: str = "hecate"
    db_password: str = "hecate"
    db_name: str = "hecate_sentinel"
    db_pool_size: int = 5
    db_max_overflow: int = 10

    @property
    def database_url(self) -> str:
        return f"postgresql+asyncpg://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    # CORS
    cors_origins: list[str] = ["http://localhost:3000"]
    cors_allow_credentials: bool = True
    cors_allow_methods: list[str] = ["*"]
    cors_allow_headers: list[str] = ["*"]

    # Trusted Hosts
    trusted_hosts: list[str] = ["localhost", "127.0.0.1"]

    # GZip
    gzip_minimum_size: int = 1000

    # Request ID
    request_id_header: str = "X-Request-ID"

    # Security / JWT
    secret_key: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "hecate-sentinel"
    jwt_audience: str = "hecate-sentinel-api"
    access_token_expire_minutes: int = 30

    # Authentication
    allow_registration: bool = False
    refresh_token_expire_days: int = 7
    magic_link_expire_minutes: int = 15
    password_reset_expire_minutes: int = 60
    email_verification_expire_hours: int = 24

    # SMTP Email
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True
    smtp_from_email: str = "noreply@example.com"
    smtp_from_name: str = "Hecate Sentinel"

    # Application URLs
    frontend_url: str = "http://localhost:3000"

    # OAuth - Google
    google_client_id: str | None = None
    google_client_secret: str | None = None

    # OAuth - Microsoft
    microsoft_client_id: str | None = None
    microsoft_client_secret: str | None = None
    microsoft_tenant_id: str = "common"

    # OAuth General
    oauth_redirect_uri: str = "http://localhost:8000/auth/oauth/callback"
    oauth_state_expire_minutes: int = 10


@lru_cache
def get_settings() -> Settings:
    return Settings()
