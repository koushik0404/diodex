"""Deterministic evidence extraction for DIODEx explainability."""

from __future__ import annotations

from typing import Any


def _get(obj: dict | Any, key: str, default: Any = None) -> Any:
    """Read a value from a dict or ORM-like object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def build_evidence(
    flow: dict,
    detection: dict,
    baseline: dict | None = None,
) -> dict:
    """Extract deterministic factual evidence from a flow and detection.

    This function reports observations only. It does not make a security
    decision and does not use an LLM.
    """
    packet_count = _float(_get(flow, "packet_count"))
    byte_count = _float(_get(flow, "byte_count"))
    duration = _float(_get(flow, "duration"))

    source_ip = str(_get(flow, "source_ip", ""))
    destination_ip = str(_get(flow, "destination_ip", ""))
    source_port = int(_float(_get(flow, "source_port", 0)))
    destination_port = int(_float(_get(flow, "destination_port", 0)))
    protocol = str(_get(flow, "protocol", ""))

    packets_per_second = (
        packet_count / duration if duration > 0 else 0.0
    )
    bytes_per_second = (
        byte_count / duration if duration > 0 else 0.0
    )

    threat_name = str(_get(detection, "threat_name", "normal")).lower()
    confidence = _float(_get(detection, "confidence"))
    anomaly_score = _float(_get(detection, "anomaly_score"))

    signals: list[dict] = []

    # Only known threat classes are reported as known-threat classifications.
    # "unknown" is produced by the anomaly detector and is not a known class.
    if threat_name not in {"normal", "unknown", ""}:
        signals.append(
            {
                "name": "known_threat_classification",
                "value": threat_name,
                "description": (
                    f"Known-threat detector classified the flow as "
                    f"{threat_name}."
                ),
            }
        )

    # High packet-rate observation.
    if packets_per_second >= 1000:
        signals.append(
            {
                "name": "high_packet_rate",
                "value": packets_per_second,
                "description": (
                    f"Packet rate is {packets_per_second:.1f} packets/sec."
                ),
            }
        )

    # High byte-rate observation.
    if bytes_per_second >= 1_000_000:
        signals.append(
            {
                "name": "high_byte_rate",
                "value": bytes_per_second,
                "description": (
                    f"Byte rate is {bytes_per_second:.1f} bytes/sec."
                ),
            }
        )

    # Very short flow.
    if 0 < duration <= 0.1:
        signals.append(
            {
                "name": "very_short_duration",
                "value": duration,
                "description": (
                    f"Flow duration is only {duration:.3f} seconds."
                ),
            }
        )

    # Known-threat confidence.
    if confidence > 0:
        signals.append(
            {
                "name": "detector_confidence",
                "value": confidence,
                "description": (
                    f"Known-threat detector confidence is {confidence:.2%}."
                ),
            }
        )

    # High anomaly score.
    if anomaly_score >= 0.5:
        signals.append(
            {
                "name": "high_anomaly_score",
                "value": anomaly_score,
                "description": (
                    f"Isolation Forest anomaly score is "
                    f"{anomaly_score:.3f}."
                ),
            }
        )

    # Baseline deviation.
    # Expected structure:
    # {
    #     "packets_per_second": {"mean": 10.0, "std": 10.0},
    #     "bytes_per_second": {"mean": ..., "std": ...},
    # }
    if baseline:
        packet_baseline = baseline.get("packets_per_second")
        if isinstance(packet_baseline, dict):
            mean = _float(packet_baseline.get("mean"))
            std = _float(packet_baseline.get("std"))

            if std > 0:
                z_score = abs(packets_per_second - mean) / std

                if z_score >= 3.0:
                    signals.append(
                        {
                            "name": "baseline_deviation_packets_per_second",
                            "value": packets_per_second,
                            "baseline_mean": mean,
                            "baseline_std": std,
                            "z_score": z_score,
                            "description": (
                                f"Packet rate is {z_score:.1f} standard "
                                f"deviations from the provided baseline."
                            ),
                        }
                    )

        byte_baseline = baseline.get("bytes_per_second")
        if isinstance(byte_baseline, dict):
            mean = _float(byte_baseline.get("mean"))
            std = _float(byte_baseline.get("std"))

            if std > 0:
                z_score = abs(bytes_per_second - mean) / std

                if z_score >= 3.0:
                    signals.append(
                        {
                            "name": "baseline_deviation_bytes_per_second",
                            "value": bytes_per_second,
                            "baseline_mean": mean,
                            "baseline_std": std,
                            "z_score": z_score,
                            "description": (
                                f"Byte rate is {z_score:.1f} standard "
                                f"deviations from the provided baseline."
                            ),
                        }
                    )

    return {
        "metrics": {
            "packet_count": packet_count,
            "byte_count": byte_count,
            "duration": duration,
            "packets_per_second": packets_per_second,
            "bytes_per_second": bytes_per_second,
        },
        "network": {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
        },
        "signals": signals,
    }