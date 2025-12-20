"""Tests for security utilities."""

from datetime import timedelta

import pytest

from src.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_secure_token,
    hash_password,
    password_needs_rehash,
    verify_password,
)


class TestPasswordHashing:
    """Tests for password hashing functions."""

    def test_hash_password(self):
        """Test password hashing produces a hash."""
        password = "SecurePassword123!"
        hashed = hash_password(password)

        assert hashed != password
        assert len(hashed) > 50  # Argon2 hashes are long
        assert hashed.startswith("$argon2")

    def test_hash_password_different_each_time(self):
        """Test that same password produces different hashes (salt)."""
        password = "SecurePassword123!"

        hash1 = hash_password(password)
        hash2 = hash_password(password)

        assert hash1 != hash2

    def test_verify_password_correct(self):
        """Test verifying correct password."""
        password = "SecurePassword123!"
        hashed = hash_password(password)

        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Test verifying incorrect password."""
        password = "SecurePassword123!"
        hashed = hash_password(password)

        assert verify_password("WrongPassword", hashed) is False

    def test_verify_password_invalid_hash(self):
        """Test verifying against invalid hash."""
        assert verify_password("password", "invalid_hash") is False

    def test_password_needs_rehash_current(self):
        """Test that current hash doesn't need rehashing."""
        password = "SecurePassword123!"
        hashed = hash_password(password)

        assert password_needs_rehash(hashed) is False


class TestJWTTokens:
    """Tests for JWT token functions."""

    def test_create_access_token(self):
        """Test creating an access token."""
        data = {"sub": "user123", "email": "user@example.com"}
        token = create_access_token(data)

        assert isinstance(token, str)
        assert len(token) > 50

    def test_create_access_token_custom_expiry(self):
        """Test creating access token with custom expiry."""
        data = {"sub": "user123"}
        token = create_access_token(data, expires_delta=timedelta(hours=1))

        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["type"] == "access"

    def test_create_refresh_token(self):
        """Test creating a refresh token."""
        data = {"sub": "user123"}
        token = create_refresh_token(data)

        assert isinstance(token, str)
        assert len(token) > 50

    def test_refresh_token_has_correct_type(self):
        """Test that refresh token has correct type claim."""
        data = {"sub": "user123"}
        token = create_refresh_token(data)

        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["type"] == "refresh"

    def test_access_token_has_correct_type(self):
        """Test that access token has correct type claim."""
        data = {"sub": "user123"}
        token = create_access_token(data)

        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["type"] == "access"

    def test_decode_token_valid(self):
        """Test decoding a valid token."""
        data = {"sub": "user123", "custom": "data"}
        token = create_access_token(data)

        decoded = decode_token(token)

        assert decoded is not None
        assert decoded["sub"] == "user123"
        assert decoded["custom"] == "data"
        assert "exp" in decoded

    def test_decode_token_invalid(self):
        """Test decoding an invalid token."""
        decoded = decode_token("invalid.token.here")

        assert decoded is None

    def test_decode_token_tampered(self):
        """Test decoding a tampered token."""
        data = {"sub": "user123"}
        token = create_access_token(data)

        # Tamper with the token
        tampered = token[:-5] + "xxxxx"

        decoded = decode_token(tampered)
        assert decoded is None

    def test_token_contains_original_data(self):
        """Test that token contains original data after decode."""
        data = {"sub": "user456", "role": "admin", "permissions": ["read", "write"]}
        token = create_access_token(data)

        decoded = decode_token(token)

        assert decoded["sub"] == "user456"
        assert decoded["role"] == "admin"
        assert decoded["permissions"] == ["read", "write"]


class TestSecureTokenGeneration:
    """Tests for secure token generation."""

    def test_generate_secure_token_default_length(self):
        """Test generating token with default length."""
        token = generate_secure_token()

        assert isinstance(token, str)
        assert len(token) > 30  # URL-safe base64 of 32 bytes

    def test_generate_secure_token_custom_length(self):
        """Test generating token with custom length."""
        token = generate_secure_token(length=64)

        assert isinstance(token, str)
        assert len(token) > 60

    def test_generate_secure_token_unique(self):
        """Test that generated tokens are unique."""
        tokens = [generate_secure_token() for _ in range(100)]

        assert len(set(tokens)) == 100

    def test_generate_secure_token_url_safe(self):
        """Test that token is URL-safe."""
        token = generate_secure_token()

        # URL-safe base64 only contains these characters
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        assert all(c in valid_chars for c in token)
