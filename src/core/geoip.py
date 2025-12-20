"""GeoIP service for IP address geolocation."""

import hashlib
import ipaddress
import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

# ip-api.com free tier: 45 requests per minute, no API key needed
GEOIP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp"
GEOIP_TIMEOUT = 5.0


@dataclass
class GeoLocation:
    """Geolocation data from IP lookup."""

    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None
    isp: str | None = None


async def get_geolocation(ip_address: str) -> GeoLocation:
    """
    Get geolocation data for an IP address.

    Uses ip-api.com free API (no key required).
    Rate limited to 45 requests/minute.
    Returns empty GeoLocation for private/local IPs.
    """
    # Skip for private/local IPs
    if _is_private_ip(ip_address):
        return GeoLocation()

    try:
        async with httpx.AsyncClient(timeout=GEOIP_TIMEOUT) as client:
            response = await client.get(GEOIP_API_URL.format(ip=ip_address))

            if response.status_code != 200:
                logger.warning(f"GeoIP lookup failed with status {response.status_code}")
                return GeoLocation()

            data = response.json()

            if data.get("status") != "success":
                logger.warning(
                    f"GeoIP lookup failed: {data.get('message', 'Unknown error')}"
                )
                return GeoLocation()

            return GeoLocation(
                country=data.get("country"),
                country_code=data.get("countryCode"),
                region=data.get("regionName"),
                city=data.get("city"),
                latitude=data.get("lat"),
                longitude=data.get("lon"),
                timezone=data.get("timezone"),
                isp=data.get("isp"),
            )
    except httpx.TimeoutException:
        logger.warning(f"GeoIP lookup timed out for {ip_address}")
        return GeoLocation()
    except Exception as e:
        logger.error(f"GeoIP lookup error for {ip_address}: {e}")
        return GeoLocation()


def _is_private_ip(ip_address: str) -> bool:
    """Check if IP is private/localhost."""
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private or ip.is_loopback or ip.is_reserved
    except ValueError:
        return True


def create_location_fingerprint(country: str | None, city: str | None) -> str:
    """Create a fingerprint for location comparison."""
    location_str = f"{country or 'unknown'}:{city or 'unknown'}".lower()
    return hashlib.sha256(location_str.encode()).hexdigest()
