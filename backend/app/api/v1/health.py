"""NetDigno — health endpoint."""
from __future__ import annotations

from fastapi import APIRouter
from app.services.nmap_service import nmap_available

router = APIRouter()


@router.get("/health")
async def health_check():
    """
    Application health check.
    Returns service status and nmap availability.
    Does not expose internal system details.
    """
    return {
        "status": "ok",
        "service": "netdigno",
        "version": "1.0.0",
        "nmap_available": nmap_available(),
    }
