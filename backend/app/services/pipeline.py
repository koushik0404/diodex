"""Unified DIODEx detection and intelligence pipeline."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Any

from app.explanation.evidence import build_evidence
from app.explanation.formatter import format_explanation
from app.explanation.llm import generate_explanation
from app.explanation.reasoning import build_reasoning
from app.intelligence.correlation import correlate_alerts
from app.intelligence.deduplication import deduplicate_alerts
from app.intelligence.prioritization import prioritize_incidents

NORMAL_CLASS = "normal"
UNKNOWN_CLASS = "unknown"

Detector = Callable[[dict], dict]


def _flow_get(flow: Any, name: str):
    """Read a field from a dict or ORM-like object."""
    if isinstance(flow, dict):
        return flow.get(name)
    return getattr(flow, name, None)


def _iso_timestamp(flow: Any) -> str:
    """Return a JSON-safe UTC ISO timestamp."""
    value = _flow_get(flow, "timestamp")

    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()

    return str(value).replace("Z", "+00:00")


def _default_known(flow: dict) -> dict:
    from app.detection.engine import predict_known_threat

    return predict_known_threat(flow)


def _default_anomaly(flow: dict) -> dict:
    from app.anomaly.isolation_forest import predict_anomaly

    return predict_anomaly(flow)


def _build_alert(
    flow: dict,
    detection: dict,
) -> dict:
    """Build a base alert from a detector result."""
    return {
        "timestamp": _iso_timestamp(flow),
        "source_ip": str(_flow_get(flow, "source_ip") or ""),
        "destination_ip": str(_flow_get(flow, "destination_ip") or ""),
        "threat_name": str(
            detection.get("threat_name") or NORMAL_CLASS
        ),
        "confidence": float(detection.get("confidence") or 0.0),
        "anomaly_score": float(
            detection.get("anomaly_score") or 0.0
        ),
    }


def _attach_explainability(
    flow: dict,
    detection: dict,
    alert: dict,
    include_llm: bool = False,
) -> dict:
    """Attach deterministic evidence/reasoning and optional LLM text."""
    evidence = build_evidence(flow, detection)
    reasoning = build_reasoning(detection, evidence)
    formatted = format_explanation(
        detection,
        reasoning,
        evidence,
    )

    alert["evidence"] = evidence
    alert["reasoning"] = reasoning
    alert["explanation"] = formatted

    if include_llm:
        ai_explanation = generate_explanation(
            detection,
            evidence,
        )
        alert["explanation"]["ai_explanation"] = ai_explanation

    return alert


def run_detection_on_flow(
    flow: dict,
    predict_known: Detector | None = None,
    predict_anomaly: Detector | None = None,
    include_llm: bool = False,
) -> dict | None:
    """Run both detectors and produce at most one alert.

    Rules:
      * Known threat -> one known-threat alert.
      * Known threat never creates a second unknown alert.
      * Normal + Isolation Forest anomaly -> one unknown alert.
      * Normal + no anomaly -> no alert.
    """
    known = (
        predict_known(flow)
        if predict_known
        else _default_known(flow)
    )

    anomaly = (
        predict_anomaly(flow)
        if predict_anomaly
        else _default_anomaly(flow)
    )

    anomaly_score = float(
        anomaly.get("anomaly_score") or 0.0
    )

    threat_name = str(
        known.get("threat_name") or NORMAL_CLASS
    ).lower()

    detection = {
        "threat_name": threat_name,
        "confidence": float(
            known.get("confidence") or 0.0
        ),
        "anomaly_score": anomaly_score,
    }

    if threat_name != NORMAL_CLASS:
        alert = _build_alert(flow, detection)
        return _attach_explainability(
            flow,
            detection,
            alert,
            include_llm=include_llm,
        )

    if anomaly.get("is_anomaly"):
        detection["threat_name"] = UNKNOWN_CLASS
        detection["confidence"] = 0.0

        alert = _build_alert(flow, detection)

        return _attach_explainability(
            flow,
            detection,
            alert,
            include_llm=include_llm,
        )

    return None


def run_pipeline(
    flows: list[dict],
    window_seconds: int = 300,
    predict_known: Detector | None = None,
    predict_anomaly: Detector | None = None,
    include_llm: bool = False,
) -> dict:
    """Run detection, explainability, correlation and prioritization."""
    alerts: list[dict] = []

    for flow in flows:
        alert = run_detection_on_flow(
            flow,
            predict_known=predict_known,
            predict_anomaly=predict_anomaly,
            include_llm=include_llm,
        )

        if alert is not None:
            alerts.append(alert)

    unique_alerts = deduplicate_alerts(
        alerts,
        window_seconds=window_seconds,
    )

    incidents = correlate_alerts(
        unique_alerts,
        window_seconds=window_seconds,
    )

    prioritized = prioritize_incidents(incidents)

    summary = {
        "total_flows": len(flows),
        "total_alerts": len(unique_alerts),
        "total_incidents": len(prioritized),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for incident in prioritized:
        priority = str(
            incident["priority"]
        ).lower()
        summary[priority] += 1

    return {
        "alerts": unique_alerts,
        "incidents": prioritized,
        "summary": summary,
    }