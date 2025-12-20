"""Request context utilities for extracting client information."""

from dataclasses import dataclass

from fastapi import Request


@dataclass
class RequestContext:
    """Context information from the current request."""

    ip_address: str
    user_agent: str
    request_id: str | None = None


def get_request_context(request: Request) -> RequestContext:
    """Extract context information from a FastAPI request."""
    # Get client IP, considering proxy headers
    ip_address = _get_client_ip(request)

    # Get user agent
    user_agent = request.headers.get("user-agent", "")

    # Get request ID if available (from fastapi-reqid or similar)
    request_id = request.headers.get("x-request-id")

    return RequestContext(
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
    )


def _get_client_ip(request: Request) -> str:
    """
    Get the real client IP address, considering reverse proxies.

    Checks X-Forwarded-For and X-Real-IP headers first.
    """
    # Check X-Forwarded-For header (can have multiple IPs)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # Take the first IP (original client)
        return forwarded_for.split(",")[0].strip()

    # Check X-Real-IP header
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    # Fall back to direct client IP
    if request.client:
        return request.client.host

    return "unknown"
