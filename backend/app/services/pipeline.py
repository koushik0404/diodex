"""Unified DIODEx detection pipeline.

Connects: flow data -> feature extraction (inside the detectors)
-> Random Forest known-threat detection -> Isolation Forest anomaly
detection -> alert creation -> deduplication -> correlation into incidents
-> risk scoring -> prioritization.

Independent of FastAPI and PostgreSQL: it consumes Flow-compatible dicts
(or ORM instances) and returns JSON-serializable dictionaries.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from app.intelligence.correlation import correlate_alerts
from app.intelligence.deduplication import deduplicate_alerts
from app.intelligence.prioritization import prioritize_incidents

NORMAL_CLASS = "normal"
UNKNOWN_CLASS = "unknown"

# Detector callable signatures:
#   predict_known(flow)  -> {"threat_name": str, "confidence": float, ...}
#   predict_anomaly(flow)-> {"is_anomaly": bool, "anomaly_score": float}
Detector = Callable[[dict], dict]


def _flow_get(flow, name: str):
    """Read a field from a dict or an ORM-like object."""
    if isinstance(flow, dict):
        return flow.get(name)
    return getattr(flow, name, None)


def _iso_timestamp(flow) -> str:
    """JSON-safe UTC ISO timestamp from a datetime or ISO string."""
    value = _flow_get(flow, "timestamp")
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    # Canonicalize a trailing "Z" so all downstream modules agree.
    return str(value).replace("Z", "+00:00")


def _default_known(flow: dict) -> dict:
    from app.detection.engine import predict_known_threat

    return predict_known_threat(flow)


def _default_anomaly(flow: dict) -> dict:
    from app.anomaly.isolation_forest import predict_anomaly

    return predict_anomaly(flow)


def run_detection_on_flow(
    flow: dict,
    predict_known: Detector | None = None,
    predict_anomaly: Detector | None = None,
) -> dict | None:
    """Run both detectors on one flow and create at most one alert.

    Rules:
      * Known threat from Random Forest -> one known-threat alert
        (never a second "unknown" alert for the same flow).
      * RF says "normal" AND Isolation Forest flags it -> "unknown" alert.
      * RF says "normal" and no anomaly        -> no alert (None).

    Detectors can be injected for testing; they default to the trained
    models in backend/artifacts (loaded lazily on first call).
    """
    known = predict_known(flow) if predict_known else _default_known(flow)
    anomaly = (
        predict_anomaly(flow)
        if predict_anomaly
        else _default_anomaly(flow)
    )

    timestamp = _iso_timestamp(flow)
    source_ip = str(_flow_get(flow, "source_ip"))
    destination_ip = str(_flow_get(flow, "destination_ip"))
    anomaly_score = float(anomaly.get("anomaly_score") or 0.0)

    threat_name = str(known.get("threat_name") or NORMAL_CLASS)
    if threat_name != NORMAL_CLASS:
        # Known threat wins; the Isolation Forest signal is preserved on the
        # alert as metadata but does not spawn a second alert.
        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "threat_name": threat_name,
            "confidence": float(known.get("confidence") or 0.0),
            "anomaly_score": anomaly_score,
        }

    if anomaly.get("is_anomaly"):
        # RF saw nothing known, but Isolation Forest sees an outlier.
        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "threat_name": UNKNOWN_CLASS,
            "confidence": 0.0,  # no known-threat confidence for this class
            "anomaly_score": anomaly_score,
        }

    return None


def run_pipeline(
    flows: list[dict],
    window_seconds: int = 300,
    predict_known: Detector | None = None,
    predict_anomaly: Detector | None = None,
) -> dict:
    """Run detection + intelligence over a batch of flows.

    Returns JSON-serializable:
        {"alerts": [...], "incidents": [...], "summary": {...}}
    """
    alerts: list[dict] = []
    for flow in flows:
        alert = run_detection_on_flow(flow, predict_known, predict_anomaly)
        if alert is not None:
            alerts.append(alert)

    unique_alerts = deduplicate_alerts(alerts, window_seconds=window_seconds)
    incidents = correlate_alerts(unique_alerts, window_seconds=window_seconds)
    prioritized = prioritize_incidents(incidents)

    summary: dict = {
        "total_flows": len(flows),
        "total_alerts": len(unique_alerts),
        "total_incidents": len(prioritized),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    for incident in prioritized:
        summary[str(incident["priority"]).lower()] += 1

    return {
        "alerts": unique_alerts,
        "incidents": prioritized,
        "summary": summary,
    }
