"""Deterministic 0-100 risk scoring for DIODEx incidents (no LLM).

Risk is severity-anchored: the threat type sets the base, confidence /
anomaly belief scales it toward its ceiling, and the number of correlated
alerts adds a bounded volume bonus. All inputs default to 0.0 when absent
so missing metadata never adds phantom risk.
"""

from __future__ import annotations

# Inherent severity of each known threat type (0-100).
THREAT_SEVERITY: dict[str, int] = {
    "exfil": 85,
    "ddos": 80,
    "c2": 75,
    "unknown": 70,
    "tls": 60,
    "dga": 55,
    "scan": 35,
}
DEFAULT_SEVERITY = 50  # for any unrecognized threat_name

# Volume bonus: +2 per extra correlated alert, capped.
VOLUME_BONUS_MAX = 20
VOLUME_BONUS_STEP = 2


def severity_for(threat_name: str | None) -> int:
    return THREAT_SEVERITY.get(str(threat_name or "").lower(), DEFAULT_SEVERITY)


def _belief(confidence, anomaly_score) -> float:
    """How strongly we trust this is really the flagged behavior (0..1)."""
    return max(float(confidence or 0.0), float(anomaly_score or 0.0))


def _risk(severity: int, confidence, anomaly_score, count: int) -> int:
    belief = _belief(confidence, anomaly_score)
    count = max(1, int(count))
    volume = min(VOLUME_BONUS_MAX, (count - 1) * VOLUME_BONUS_STEP)
    raw = severity * (0.5 + 0.5 * belief) + volume
    return int(max(0, min(100, round(raw))))


def score_alert(alert: dict, alert_count: int = 1) -> int:
    """Risk score (0-100) for a single alert dict."""
    return _risk(
        severity_for(alert.get("threat_name")),
        alert.get("confidence"),
        alert.get("anomaly_score"),
        alert_count,
    )


def score_incident(incident: dict) -> int:
    """Risk score (0-100) for an incident dict with an 'alerts' list.

    Aggregates conservatively: worst threat severity, strongest
    confidence, strongest anomaly signal, total correlated alert count.
    """
    alerts = incident.get("alerts") or []
    if not alerts:
        return 0
    severity = max(severity_for(a.get("threat_name")) for a in alerts)
    confidence = max(float(a.get("confidence") or 0.0) for a in alerts)
    anomaly = max(float(a.get("anomaly_score") or 0.0) for a in alerts)
    return _risk(severity, confidence, anomaly, len(alerts))
