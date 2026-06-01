"""Utility helpers: config loader, geo math, mock geo-lookup."""

import math
from pathlib import Path
from typing import Optional

import yaml  # type: ignore[import-untyped]


def load_config(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometers between two lat/lon points."""
    R = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


# Static mock lookup using TEST-NET IP ranges (RFC 5737)
# These are not real locations — chosen purely for demo distances.
_MOCK_GEO = {
    # U.S. documentation block 192.0.2.0/24
    "192.0.2.10": {"lat": 34.0522, "lon": -118.2437, "city": "Los_Angeles", "country": "US"},
    "192.0.2.20": {"lat": 40.7128, "lon": -74.0060, "city": "New_York", "country": "US"},
    "192.0.2.30": {"lat": 51.5074, "lon": -0.1278, "city": "London", "country": "GB"},
    "192.0.2.40": {"lat": 35.6762, "lon": 139.6503, "city": "Tokyo", "country": "JP"},
    "192.0.2.50": {"lat": 48.8566, "lon": 2.3522, "city": "Paris", "country": "FR"},
    "192.0.2.60": {"lat": -33.8688, "lon": 151.2093, "city": "Sydney", "country": "AU"},
    "192.0.2.70": {"lat": 55.7558, "lon": 37.6173, "city": "Moscow", "country": "RU"},
    # TEST-NET-2 198.51.100.0/24
    "198.51.100.5": {"lat": 37.7749, "lon": -122.4194, "city": "San_Francisco", "country": "US"},
    "198.51.100.15": {"lat": 1.3521, "lon": 103.8198, "city": "Singapore", "country": "SG"},
    # TEST-NET-3 203.0.113.0/24
    "203.0.113.8": {"lat": 52.5200, "lon": 13.4050, "city": "Berlin", "country": "DE"},
    "203.0.113.22": {"lat": 19.0760, "lon": 72.8777, "city": "Mumbai", "country": "IN"},
}


def mock_geo_lookup(ip: str) -> Optional[dict]:
    """Return synthetic geolocation for well-known test IPs; None otherwise."""
    return _MOCK_GEO.get(ip)
