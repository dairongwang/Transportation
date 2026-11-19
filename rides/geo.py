"""
Geocoding and routing.

The app needs two things from a maps provider: turn an address into coordinates, and
estimate distance / travel time between two points. Both are behind a tiny interface so
a real provider (Google Maps, Mapbox, OSRM, ...) can be plugged in later with
MAPS_BACKEND=<name> and MAPS_API_KEY. Only the offline STUB ships with the demo:

  * StubGeocoder  - "lat,lng" strings are parsed as-is; a handful of fictional landmarks
                    ("Airport", "Downtown", ...) map to fixed points; any other text is
                    hashed into a deterministic point inside the demo city, so the same
                    address always lands on the same spot and no internet is needed.
  * StubRouter    - great-circle distance x a road-detour factor, at a flat average speed.

Coordinates are WGS84 decimal degrees. Distances are kilometres, durations minutes.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass

from flask import current_app

EARTH_RADIUS_KM = 6371.0088

# A fictional "Demo City" (nothing here corresponds to a real address).
DEMO_CITY_CENTER = (40.0000, -75.0000)
DEMO_CITY_RADIUS_KM = 7.0

# name -> (lat, lng). Offsets are a few km around the centre.
LANDMARKS: dict[str, tuple[float, float]] = {
    "Downtown": (40.0000, -75.0000),
    "Central Station": (40.0080, -74.9920),
    "Airport": (39.9650, -74.9150),
    "University": (40.0260, -75.0180),
    "Harbor": (39.9800, -75.0400),
    "Stadium": (40.0150, -74.9650),
    "Mall": (39.9900, -74.9700),
    "Hospital": (40.0050, -75.0230),
    "Old Town": (39.9940, -75.0080),
    "Tech Park": (40.0350, -74.9700),
}

_LATLNG_RE = re.compile(r"^\s*(-?\d{1,2}(?:\.\d+)?)\s*,\s*(-?\d{1,3}(?:\.\d+)?)\s*$")


class GeoError(ValueError):
    """Raised when a location cannot be resolved."""


@dataclass(frozen=True)
class GeoPoint:
    lat: float
    lng: float
    label: str = ""

    def as_dict(self) -> dict:
        return {"lat": round(self.lat, 6), "lng": round(self.lng, 6), "label": self.label}


@dataclass(frozen=True)
class RouteEstimate:
    distance_km: float
    duration_min: float

    def as_dict(self) -> dict:
        return {"distance_km": round(self.distance_km, 2), "duration_min": round(self.duration_min, 1)}


def haversine_km(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """Great-circle distance between two WGS84 points."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = p2 - p1
    dlmb = math.radians(lng2 - lng1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def offset_point(lat: float, lng: float, north_km: float, east_km: float) -> tuple[float, float]:
    """Move a point by a small north/east offset (flat-earth approximation, fine for a city)."""
    dlat = north_km / 110.574
    dlng = east_km / (111.320 * math.cos(math.radians(lat)) or 1e-9)
    return lat + dlat, lng + dlng


# ----------------------------------------------------------------- interfaces

class Geocoder:
    def geocode(self, text: str) -> GeoPoint:  # pragma: no cover - interface
        raise NotImplementedError


class Router:
    def route(self, origin: GeoPoint, destination: GeoPoint) -> RouteEstimate:  # pragma: no cover
        raise NotImplementedError


# ----------------------------------------------------------------- stub backend

class StubGeocoder(Geocoder):
    """Offline, deterministic geocoder for development and tests."""

    def geocode(self, text: str) -> GeoPoint:
        text = (text or "").strip()
        if not text:
            raise GeoError("Please enter a location.")
        if len(text) > 200:
            raise GeoError("Location is too long.")

        m = _LATLNG_RE.match(text)
        if m:
            lat, lng = float(m.group(1)), float(m.group(2))
            if not (-90 <= lat <= 90 and -180 <= lng <= 180):
                raise GeoError("Coordinates are out of range.")
            return GeoPoint(lat, lng, f"{lat:.5f}, {lng:.5f}")

        lowered = text.lower()
        for name, (lat, lng) in LANDMARKS.items():
            if name.lower() in lowered:
                return GeoPoint(lat, lng, name)

        # Unknown free text: hash it into a stable point inside the demo city.
        digest = hashlib.sha256(lowered.encode("utf-8")).digest()
        angle = int.from_bytes(digest[:4], "big") / 2**32 * 2 * math.pi
        radius = math.sqrt(int.from_bytes(digest[4:8], "big") / 2**32) * DEMO_CITY_RADIUS_KM
        lat, lng = offset_point(*DEMO_CITY_CENTER, radius * math.cos(angle), radius * math.sin(angle))
        return GeoPoint(lat, lng, text[:100])


class StubRouter(Router):
    """Straight-line distance with a detour factor and a flat average city speed."""

    DETOUR_FACTOR = 1.3
    AVERAGE_SPEED_KMH = 30.0
    FIXED_OVERHEAD_MIN = 1.0  # pulling out, stopping, ...

    def route(self, origin: GeoPoint, destination: GeoPoint) -> RouteEstimate:
        straight = haversine_km(origin.lat, origin.lng, destination.lat, destination.lng)
        distance = straight * self.DETOUR_FACTOR
        duration = distance / self.AVERAGE_SPEED_KMH * 60 + self.FIXED_OVERHEAD_MIN
        return RouteEstimate(distance_km=distance, duration_min=duration)


# ----------------------------------------------------------------- factory

_BACKENDS: dict[str, tuple[type[Geocoder], type[Router]]] = {
    "stub": (StubGeocoder, StubRouter),
}


def backend_name() -> str:
    try:
        return current_app.config.get("MAPS_BACKEND", "stub")
    except RuntimeError:  # outside app context
        return "stub"


def get_geocoder() -> Geocoder:
    name = backend_name()
    if name not in _BACKENDS:
        raise RuntimeError(f"MAPS_BACKEND={name!r} is not implemented; available: {', '.join(_BACKENDS)}")
    return _BACKENDS[name][0]()


def get_router() -> Router:
    name = backend_name()
    if name not in _BACKENDS:
        raise RuntimeError(f"MAPS_BACKEND={name!r} is not implemented; available: {', '.join(_BACKENDS)}")
    return _BACKENDS[name][1]()


def landmark_names() -> list[str]:
    return list(LANDMARKS)


def nearest_landmark(lat: float, lng: float) -> tuple[str, float]:
    """(name, distance_km) of the closest landmark - used to describe raw GPS coordinates."""
    name, (llat, llng) = min(LANDMARKS.items(), key=lambda kv: haversine_km(lat, lng, kv[1][0], kv[1][1]))
    return name, haversine_km(lat, lng, llat, llng)


def looks_like_coords(label: str | None) -> bool:
    return bool(label) and _LATLNG_RE.match(label) is not None


def describe(label: str | None, lat: float | None, lng: float | None, mode: str = "landmark") -> str:
    """
    Render a place for display. mode "gps" -> "40.00300, -75.00100"; mode "landmark" -> the
    address/landmark label, or for raw coordinates the nearest landmark ("near Downtown, 0.3 km").
    """
    if lat is None or lng is None:
        return label or "?"
    if mode == "gps":
        return f"{lat:.5f}, {lng:.5f}"
    if looks_like_coords(label) or not label:
        name, km = nearest_landmark(lat, lng)
        if km < 0.05:
            return name
        return f"near {name} ({km:.1f} km)" if km < 25 else f"{lat:.5f}, {lng:.5f}"
    return label
