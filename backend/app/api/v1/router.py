"""NetDigno — API v1 router aggregator."""
from fastapi import APIRouter

from app.api.v1 import health, diagnostics, scans

api_router = APIRouter()
api_router.include_router(health.router, tags=["health"])
api_router.include_router(diagnostics.router, prefix="/diagnostics", tags=["diagnostics"])
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
