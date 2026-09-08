"""UI-friendly formatting for DIODEx explainability."""

from __future__ import annotations

from typing import Any


def format_explanation(
    detection: dict[str, Any],
    reasoning: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Convert reasoning + evidence into dashboard-friendly data."""
    threat_name = str(
        detection.get("threat_name")
        or reasoning.get("threat_name")
        or "normal"
    ).lower()

    confidence = detection.get("confidence")
    anomaly_score = detection.get("anomaly_score")

    confidence_text = (
        f"{float(confidence):.0%}"
        if confidence is not None
        else None
    )

    anomaly_text = (
        f"{float(anomaly_score):.2f}"
        if anomaly_score is not None
        else None
    )

    signals = evidence.get("signals") or []

    evidence_items: list[dict[str, Any]] = []

    for signal in signals:
        evidence_items.append(
            {
                "title": str(signal.get("name", "")).replace("_", " ").title(),
                "description": str(signal.get("description", "")),
                "value": signal.get("value"),
            }
        )

    if threat_name == "normal":
        headline = "No known threat was detected."
    elif threat_name == "unknown":
        headline = "Unknown anomalous behavior detected."
    else:
        headline = f"{threat_name.upper()} detected."

    return {
        "headline": headline,
        "threat_name": threat_name,
        "confidence": confidence_text,
        "anomaly_score": anomaly_text,
        "conclusion": reasoning.get("conclusion", ""),
        "evidence": evidence_items,
        "reason_count": len(evidence_items),
    }