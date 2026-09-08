from fastapi import APIRouter, HTTPException

from app.ingestion.csv_loader import load_flows_from_csv
from app.services.pipeline import run_pipeline

router = APIRouter(prefix="/api", tags=["incidents"])


def _get_incidents():
    flows = load_flows_from_csv("data/ddos.csv")
    result = run_pipeline(flows[:100])
    return result["incidents"]


@router.get("/incidents")
async def get_incidents():
    """Return prioritized correlated incidents."""
    incidents = _get_incidents()

    return {
        "total_incidents": len(incidents),
        "incidents": incidents,
    }


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """Return one incident by ID."""
    incidents = _get_incidents()

    for incident in incidents:
        if incident["incident_id"] == incident_id:
            return incident

    raise HTTPException(
        status_code=404,
        detail=f"Incident {incident_id} not found",
    )