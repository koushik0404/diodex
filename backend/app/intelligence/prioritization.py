"""Risk-to-priority mapping and incident ordering for DIODEx."""

from __future__ import annotations

from datetime import datetime, timezone

from app.intelligence.risk_scoring import score_incident

PRIORITY_CRITICAL = "Critical"
PRIORITY_HIGH = "High"
PRIORITY_MEDIUM = "Medium"
PRIORITY_LOW = "Low"


def priority_from_risk(risk: int) -> str:
    """Map an integer risk score (0-100) to its priority band."""
    risk = int(risk)
    if risk >= 80:
        return PRIORITY_CRITICAL
    if risk >= 60:
        return PRIORITY_HIGH
    if risk >= 40:
        return PRIORITY_MEDIUM
    return PRIORITY_LOW


def _sortable_time(value) -> datetime:
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def prioritize_incidents(incidents: list[dict]) -> list[dict]:
    """Attach risk_score + priority and return incidents highest risk first.

    Each returned incident is a copy with added keys; input incidents are
    untouched. If an incident lacks 'risk_score' it is computed from its
    alerts via risk_scoring.score_incident.
    """
    scored: list[dict] = []
    for incident in incidents:
        risk = incident.get("risk_score")
        risk = int(risk) if risk is not None else score_incident(incident)
        out = dict(incident)
        out["risk_score"] = risk
        out["priority"] = priority_from_risk(risk)
        scored.append(out)

    scored.sort(
        key=lambda inc: (
            -inc["risk_score"],
            _sortable_time(inc.get("start_time", "")),
            str(inc.get("incident_id", "")),
        )
    )
    return scored
