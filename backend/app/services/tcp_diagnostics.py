"""NetDigno — TCP connectivity diagnostics service."""
from __future__ import annotations

import logging
import socket
import time

from app.core.config import settings
from app.schemas.diagnostics import TcpResult

logger = logging.getLogger(__name__)


def check_tcp(target: str, port: int, timeout_seconds: float | None = None) -> TcpResult:
    """
    Attempt a TCP connection to target:port.

    Uses a bounded timeout. Does NOT use shell=True or subprocess.
    A failed connection is not classified as a host outage — only as
    a connection failure at this specific time.

    Args:
        target: Hostname or IP address.
        port: TCP port number (1–65535).
        timeout_seconds: Connection timeout override.

    Returns:
        TcpResult with success flag, measured duration, and error info.
    """
    effective_timeout = timeout_seconds or settings.tcp_timeout
    logger.info("TCP check: %s:%d (timeout=%.1fs)", target, port, effective_timeout)

    start = time.perf_counter()
    timed_out = False
    error_detail: str | None = None
    success = False
    duration_ms: float | None = None

    try:
        with socket.create_connection((target, port), timeout=effective_timeout) as sock:
            elapsed = time.perf_counter() - start
            duration_ms = round(elapsed * 1000, 2)
            success = True
            logger.info("TCP connection to %s:%d succeeded in %.1fms", target, port, duration_ms)
    except socket.timeout:
        timed_out = True
        error_detail = f"Connection timed out after {effective_timeout}s."
        logger.info("TCP connection to %s:%d timed out", target, port)
    except ConnectionRefusedError:
        elapsed = time.perf_counter() - start
        duration_ms = round(elapsed * 1000, 2)
        error_detail = "Connection refused — port is closed or filtered."
        logger.info("TCP connection to %s:%d refused", target, port)
    except OSError as exc:
        error_detail = f"Network error: {exc.strerror or str(exc)}"
        logger.warning("TCP check for %s:%d failed: %s", target, port, exc)
    except Exception as exc:
        error_detail = "Unexpected error during connection attempt."
        logger.error("TCP check for %s:%d unexpected error: %s", target, port, exc)

    return TcpResult(
        target=target,
        port=port,
        success=success,
        connection_duration_ms=duration_ms,
        timed_out=timed_out,
        error_detail=error_detail,
    )
