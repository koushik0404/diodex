from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes.alerts import router as alerts_router
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.traffic import router as traffic_router
from app.api.routes.unknown import router as unknown_router
from app.models import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the database when the application starts."""
    init_db()
    yield


app = FastAPI(
    title="DIODEx API",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(alerts_router)
app.include_router(dashboard_router)
app.include_router(incidents_router)
app.include_router(traffic_router)
app.include_router(unknown_router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "DIODEx API"}