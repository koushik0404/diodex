from fastapi import APIRouter

from app.ingestion.csv_loader import load_flows_from_csv
from app.services.pipeline import run_pipeline

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/dashboard")
async def get_dashboard():
    """Return dashboard summary from prototype traffic."""
    flows = load_flows_from_csv("data/ddos.csv")
    result = run_pipeline(flows[:100])

    summary = result["summary"]

    return {
        "total_flows": summary["total_flows"],
        "total_alerts": summary["total_alerts"],
        "total_incidents": summary["total_incidents"],
        "critical": summary["critical"],
        "high": summary["high"],
        "medium": summary["medium"],
        "low": summary["low"],
    }