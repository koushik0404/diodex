"""Alert-to-incident correlation for DIODEx.

Two alerts belong to the same incident when they share source_ip OR
destination_ip and occur within a configurable time window. Correlation is
a graph connectivity problem (single-linkage over time + IP), solved with
union-find. Input is expected to be already deduplicated.
"""

from __future__ import annotations

from datetime import datetime, timezone

# Reuse the same small timestamp helpers (kept private to this package).
def _to_utc(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _normalize(alert: dict, ts: datetime) -> dict:
    out = dict(alert)
    out["timestamp"] = _iso(ts)
    return out


def _find(parent: list[int], i: int) -> int:
    while parent[i] != i:
        parent[i] = parent[parent[i]]
        i = parent[i]
    return i


def _union(parent: list[int], rank: list[int], a: int, b: int) -> None:
    ra, rb = _find(parent, a), _find(parent, b)
    if ra == rb:
        return
    if rank[ra] < rank[rb]:
        parent[ra] = rb
    elif rank[ra] > rank[rb]:
        parent[rb] = ra
    else:
        parent[rb] = ra
        rank[ra] += 1


def correlate_alerts(
    alerts: list[dict], window_seconds: int = 300
) -> list[dict]:
    """Group related alerts into incidents.

    Args:
        alerts: alert dicts (assumed deduplicated; timestamp as datetime or
            ISO string).
        window_seconds: max pairwise time gap for two alerts to correlate.

    Returns:
        Incidents sorted by start time; every alert is a JSON-safe copy with
        a UTC ISO timestamp.
    """
    if window_seconds < 0:
        raise ValueError("window_seconds must be >= 0")

    # (utc_datetime, normalized_alert_dict)
    entries = [
        (_to_utc(a["timestamp"]), _normalize(a, _to_utc(a["timestamp"])))
        for a in alerts
    ]
    n = len(entries)
    if n == 0:
        return []

    parent = list(range(n))
    rank = [0] * n
    for i in range(n):
        for j in range(i + 1, n):
            dt_i, a_i = entries[i]
            dt_j, a_j = entries[j]
            same_endpoint = (
                a_i["source_ip"] == a_j["source_ip"]
                or a_i["destination_ip"] == a_j["destination_ip"]
            )
            if same_endpoint and abs(
                (dt_i - dt_j).total_seconds()
            ) <= window_seconds:
                _union(parent, rank, i, j)

    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(_find(parent, i), []).append(i)

    incidents: list[dict] = []
    for member_idx in groups.values():
        member_alerts = [entries[i][1] for i in member_idx]
        member_alerts.sort(
            key=lambda a: (
                a["timestamp"],
                a.get("source_ip", ""),
                a.get("destination_ip", ""),
                a.get("threat_name", ""),
            )
        )
        times = [entries[i][0] for i in member_idx]
        incidents.append(
            {
                "start_time": _iso(min(times)),
                "end_time": _iso(max(times)),
                "alert_count": len(member_alerts),
                "alerts": member_alerts,
                "source_ips": sorted({a["source_ip"] for a in member_alerts}),
                "destination_ips": sorted(
                    {a["destination_ip"] for a in member_alerts}
                ),
                "threat_names": sorted(
                    {a["threat_name"] for a in member_alerts}
                ),
            }
        )

    # Deterministic ordering + stable IDs.
    incidents.sort(
        key=lambda inc: (
            inc["start_time"],
            inc["source_ips"][0] if inc["source_ips"] else "",
            inc["destination_ips"][0] if inc["destination_ips"] else "",
            inc["threat_names"][0] if inc["threat_names"] else "",
        )
    )
    for idx, incident in enumerate(incidents, start=1):
        incident["incident_id"] = f"INC-{idx:04d}"
    return incidents
