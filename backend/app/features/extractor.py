"""Per-flow numeric feature extraction for DIODEx (no ML yet).

Turns one Flow record (ORM instance or dict) into a flat dictionary of
numeric features that Random Forest / Isolation Forest can consume later.
Raw IP addresses are intentionally excluded from the output.
"""

from __future__ import annotations

from typing import Any

# Stable, deterministic encoding for the Flow.protocol string column.
# Values are only meaningful relative to each other; trees just split on them.
PROTOCOL_CODES: dict[str, int] = {
    "tcp": 0,
    "udp": 1,
    "icmp": 2,
}
UNKNOWN_PROTOCOL_CODE = 3

# Canonical output column order (useful when building DataFrames later).
FEATURE_COLUMNS: tuple[str, ...] = (
    "packet_count",
    "byte_count",
    "duration",
    "bytes_per_packet",
    "packets_per_second",
    "bytes_per_second",
    "source_port",
    "destination_port",
    "protocol_code",
)


def _get(flow: Any, name: str) -> Any:
    """Read a field from either a Flow ORM instance or a plain dict."""
    if isinstance(flow, dict):
        return flow.get(name)
    return getattr(flow, name, None)


def _as_float(value: Any) -> float:
    """Coerce to float, treating None/empty as 0.0 (columns are non-null)."""
    try:
        return float(value) if value is not None else 0.0
    except (TypeError, ValueError):
        return 0.0


def encode_protocol(protocol: Any) -> int:
    """Numeric code for a protocol string (case-insensitive, safe fallback)."""
    if protocol is None:
        return UNKNOWN_PROTOCOL_CODE
    return PROTOCOL_CODES.get(str(protocol).strip().lower(), UNKNOWN_PROTOCOL_CODE)


def extract_features(flow: Any) -> dict[str, float]:
    """Compute ML-friendly numeric features from a single Flow record.

    Accepts either a Flow ORM instance or a dict with the Flow fields.

    Safety rules:
      * packet_count == 0  -> bytes_per_packet = 0.0 (no division by zero)
      * duration     == 0  -> packets/bytes per second = 0.0
    """
    packet_count = _as_float(_get(flow, "packet_count"))
    byte_count = _as_float(_get(flow, "byte_count"))
    duration = _as_float(_get(flow, "duration"))
    source_port = _as_float(_get(flow, "source_port"))
    destination_port = _as_float(_get(flow, "destination_port"))
    protocol = encode_protocol(_get(flow, "protocol"))

    # Derived rates -- guard the degenerate cases a flow can legitimately have.
    bytes_per_packet = byte_count / packet_count if packet_count > 0 else 0.0
    if duration > 0:
        packets_per_second = packet_count / duration
        bytes_per_second = byte_count / duration
    else:
        packets_per_second = 0.0
        bytes_per_second = 0.0

    return {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration": duration,
        "bytes_per_packet": bytes_per_packet,
        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol_code": float(protocol),
    }
