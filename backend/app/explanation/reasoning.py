"""Deterministic reasoning layer for DIODEx explainability."""

from __future__ import annotations

from typing import Any


THREAT_DESCRIPTIONS: dict[str, str] = {
    "ddos": "The flow was classified as DDoS-related traffic.",
    "c2": "The flow was classified as command-and-control traffic.",
    "dga": "The flow was classified as suspicious DNS/DGA-related traffic.",
    "tls": "The flow was classified as suspicious encrypted/TLS traffic.",
    "scan": "The flow was classified as reconnaissance or scanning traffic.",
    "exfil": "The flow was classified as potential data-exfiltration traffic.",
    "unknown": "The flow shows behavior that does not match the known threat classes.",
}


def _signal_text(signal: dict[str, Any]) -> str:
    """Convert one evidence signal into a human-readable explanation."""
    description = signal.get("description")
    if description:
        return str(description)

    name = str(signal.get("name", "unknown_signal"))
    return name.replace("_", " ").capitalize()


def build_reasoning(
    detection: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Build operator-readable reasoning from an existing detection + evidence.

    This function explains an existing security decision. It does not
    override the detector's decision and does not use an LLM.
    """
    threat_name = str(detection.get("threat_name") or "normal").lower()
    confidence = detection.get("confidence")
    anomaly_score = detection.get("anomaly_score")

    signals = evidence.get("signals") or []

    reasons: list[str] = []
    for signal in signals:
        text = _signal_text(signal)
        if text not in reasons:
            reasons.append(text)

    classification = THREAT_DESCRIPTIONS.get(
        threat_name,
        f"The flow was classified as {threat_name}.",
    )

    if threat_name == "normal":
        conclusion = "No known threat was identified by the detection layer."
    elif threat_name == "unknown":
        conclusion = (
            "The traffic was flagged as anomalous because its behavior "
            "does not match the learned normal baseline."
        )
    else:
        conclusion = classification

    return {
        "threat_name": threat_name,
        "conclusion": conclusion,
        "reasons": reasons,
        "confidence": float(confidence) if confidence is not None else None,
        "anomaly_score": (
            float(anomaly_score) if anomaly_score is not None else None
        ),
        "evidence_signal_count": len(reasons),
    }