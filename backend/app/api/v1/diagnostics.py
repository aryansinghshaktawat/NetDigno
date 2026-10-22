"""NetDigno — diagnostics API endpoints."""

import logging
from fastapi import APIRouter, Body, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings
from app.schemas.diagnostics import (
    DnsRequest, DnsResult,
    TcpRequest, TcpResult,
    RouteRequest, RouteResult,
)
from app.security.allowlist import AllowlistError, validate_target_allowed
from app.services.dns_diagnostics import resolve_dns
from app.services.tcp_diagnostics import check_tcp
from app.services.route_diagnostics import run_route_diagnostics

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)


# ── DNS ──────────────────────────────────────────────────────────────────────

@router.post("/dns", response_model=DnsResult, status_code=status.HTTP_200_OK)
@limiter.limit(settings.diagnostics_rate_limit)
async def dns_diagnostic(request: Request, body: DnsRequest = Body(...)):
    """
    Perform DNS A and AAAA lookups for the given hostname.

    Returns resolved addresses, resolution duration, and error classification.
    A resolution failure is not proof that a host is offline.
    """
    logger.info("DNS diagnostic request: %s", body.hostname)
    try:
        result = resolve_dns(body.hostname)
    except Exception as exc:
        logger.error("DNS diagnostic error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="DNS lookup failed due to an internal error.",
        )
    return result


# ── TCP ──────────────────────────────────────────────────────────────────────

@router.post("/tcp", response_model=TcpResult, status_code=status.HTTP_200_OK)
@limiter.limit(settings.diagnostics_rate_limit)
async def tcp_diagnostic(request: Request, body: TcpRequest = Body(...)):
    """
    Attempt a bounded TCP connection to target:port.

    Returns connection success, measured duration, and error detail.
    A failed connection is not classified as a host outage.
    """
    logger.info("TCP diagnostic request: %s:%d", body.target, body.port)
    try:
        validate_target_allowed(body.target)
    except AllowlistError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    try:
        result = check_tcp(body.target, body.port, body.timeout_seconds)
    except Exception as exc:
        logger.error("TCP diagnostic error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="TCP check failed due to an internal error.",
        )
    return result


# ── Route ─────────────────────────────────────────────────────────────────────

@router.post("/route", response_model=RouteResult, status_code=status.HTTP_200_OK)
@limiter.limit(settings.diagnostics_rate_limit)
async def route_diagnostic(request: Request, body: RouteRequest = Body(...)):
    """
    Run route diagnostics (traceroute/tracepath) to the target if available.

    Returns hops and raw output if supported, or a clear 'unsupported' result.
    Route diagnostics require no root privileges.
    """
    logger.info("Route diagnostic request: %s", body.target)
    try:
        result = run_route_diagnostics(body.target, body.max_hops)
    except Exception as exc:
        logger.error("Route diagnostic error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Route diagnostics failed due to an internal error.",
        )
    return result
