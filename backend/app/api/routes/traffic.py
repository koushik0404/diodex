from fastapi import APIRouter

from app.ingestion.csv_loader import load_flows_from_csv

router = APIRouter(prefix="/api", tags=["traffic"])


@router.get("/traffic")
async def get_traffic():
    """Return recent prototype network traffic."""
    flows = load_flows_from_csv("data/ddos.csv")[:100]

    return {
        "total_flows": len(flows),
        "traffic": flows,
    }