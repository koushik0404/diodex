from fastapi import APIRouter

from app.ingestion.csv_loader import load_flows_from_csv
from app.services.pipeline import run_pipeline

router = APIRouter(prefix="/api", tags=["alerts"])


@router.get("/alerts")
async def get_alerts():
    """Return detected alerts from the prototype traffic dataset."""
    flows = load_flows_from_csv("data/ddos.csv")
    result = run_pipeline(flows[:100])

    return {
        "alerts": result["alerts"],
        "total_alerts": result["summary"]["total_alerts"],
    }