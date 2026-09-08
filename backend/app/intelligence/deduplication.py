"""Duplicate-alert suppression for DIODEx.

Two alerts are duplicates when they share (source_ip, destination_ip,
threat_name) and occur within a configurable window. Uses per-key
"last-seen" semantics: a duplicate keeps refreshing the key's last time,
so a continuous burst is collapsed into one alert until a real quiet
period longer than the window passes.
"""

from __future__ import annotations

from datetime import datetime, timezone

# (source_ip, destination_ip, threat_name) -> most recent occurrence time
_Key = tuple[str, str, str]


def _to_utc(value: datetime | str) -> datetime:
    """Coerce a datetime or ISO string into a UTC-aware datetime."""
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    # fromisoformat on Python < 3.11 does not accept a trailing "Z".
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def _iso(dt: datetime) -> str:
    """Canonical JSON-safe UTC ISO representation."""
    return dt.astimezone(timezone.utc).isoformat()


def _normalize(alert: dict, ts: datetime) -> dict:
    """Return a copy of an alert with a JSON-serializable UTC timestamp."""
    out = dict(alert)
    out["timestamp"] = _iso(ts)
    return out


def deduplicate_alerts(
    alerts: list[dict], window_seconds: int = 300
) -> list[dict]:
    """Drop duplicates, keeping the earliest alert of each group.

    Args:
        alerts: alert dicts (timestamp may be datetime or ISO string).
        window_seconds: max gap between occurrences still considered
            the same continuous event.

    Returns:
        Unique alerts (copies with UTC ISO timestamps), sorted by time.
    """
    if window_seconds < 0:
        raise ValueError("window_seconds must be >= 0")

    ordered = sorted(
        alerts,
        key=lambda a: (
            _to_utc(a["timestamp"]),
            a.get("source_ip", ""),
            a.get("destination_ip", ""),
            a.get("threat_name", ""),
        ),
    )

    unique: list[dict] = []
    last_seen: dict[_Key, datetime] = {}

    for alert in ordered:
        ts = _to_utc(alert["timestamp"])
        key = (
            str(alert.get("source_ip", "")),
            str(alert.get("destination_ip", "")),
            str(alert.get("threat_name", "")),
        )
        prev = last_seen.get(key)
        if prev is not None and (ts - prev).total_seconds() <= window_seconds:
            # Duplicate: keep suppressing while the cadence stays <= window.
            last_seen[key] = ts
            continue
        unique.append(_normalize(alert, ts))
        last_seen[key] = ts

    return unique
