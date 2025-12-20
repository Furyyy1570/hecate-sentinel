"""User agent parsing utilities."""

import hashlib
from dataclasses import dataclass

from user_agents import parse


@dataclass
class DeviceInfo:
    """Parsed device information from user agent."""

    device_type: str  # mobile, tablet, desktop, bot
    browser: str | None = None
    browser_version: str | None = None
    os: str | None = None
    os_version: str | None = None
    device_brand: str | None = None
    device_model: str | None = None
    is_bot: bool = False


def parse_user_agent(user_agent_string: str) -> DeviceInfo:
    """Parse user agent string into device information."""
    ua = parse(user_agent_string)

    # Determine device type
    if ua.is_bot:
        device_type = "bot"
    elif ua.is_mobile:
        device_type = "mobile"
    elif ua.is_tablet:
        device_type = "tablet"
    else:
        device_type = "desktop"

    return DeviceInfo(
        device_type=device_type,
        browser=ua.browser.family if ua.browser.family else None,
        browser_version=ua.browser.version_string if ua.browser.version_string else None,
        os=ua.os.family if ua.os.family else None,
        os_version=ua.os.version_string if ua.os.version_string else None,
        device_brand=ua.device.brand if ua.device.brand else None,
        device_model=ua.device.model if ua.device.model else None,
        is_bot=ua.is_bot,
    )


def create_device_fingerprint(user_agent_string: str) -> str:
    """
    Create a fingerprint for device identification.

    Uses normalized browser + OS info to create a stable fingerprint
    that survives minor version updates.
    """
    ua = parse(user_agent_string)

    # Create normalized device string
    # Only use major browser/OS families, not versions
    device_str = (
        f"{ua.browser.family or 'unknown'}:"
        f"{ua.os.family or 'unknown'}:"
        f"{ua.device.family or 'unknown'}:"
        f"{'mobile' if ua.is_mobile else 'tablet' if ua.is_tablet else 'desktop'}"
    ).lower()

    return hashlib.sha256(device_str.encode()).hexdigest()


def get_device_friendly_name(device_info: DeviceInfo) -> str:
    """Generate a human-friendly device name."""
    parts = []

    if device_info.browser:
        parts.append(device_info.browser)

    if device_info.os:
        parts.append(f"on {device_info.os}")

    if device_info.device_brand and device_info.device_model:
        parts.append(f"({device_info.device_brand} {device_info.device_model})")
    elif device_info.device_type == "mobile":
        parts.append("(Mobile)")
    elif device_info.device_type == "tablet":
        parts.append("(Tablet)")

    return " ".join(parts) if parts else "Unknown Device"
