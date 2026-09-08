from fastapi import APIRouter

from app.ingestion.csv_loader import load_flows_from_csv
from app.services.pipeline import run_pipeline

router = APIRouter(prefix="/api", tags=["unknown"])


@router.get("/unknown")
async def get_unknown_threats():
    """Return flows flagged as unknown anomalous behavior."""
    flows = load_flows_from_csv("data/normal.csv")
    result = run_pipeline(flows[:100])

    unknown_alerts = [
        alert
        for alert in result["alerts"]
        if alert["threat_name"] == "unknown"
    ]

    return {
        "total_unknown": len(unknown_alerts),
        "unknown": unknown_alerts,
    }