"""NetDigno — route/traceroute diagnostics service."""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import sys
from typing import List, Optional

from app.core.config import settings
from app.schemas.diagnostics import RouteHop, RouteResult

logger = logging.getLogger(__name__)

# Regex to parse each traceroute line.
# Matches optional hop number, optional RTT value, optional address.
_HOP_RE = re.compile(
    r"^\s*(\d+)\s+(?:"
    r"(\*)|"  # timeout hop
    r"(?:[\w\.-]+\s+)?\(?([\d\.a-fA-F:]+)\)?\s+(\d+\.?\d*)\s*ms"
    r")"
)


def _find_tracer() -> Optional[str]:
    """Return the path to traceroute/tracepath if available, else None."""
    for candidate in ("traceroute", "tracepath", "tracert"):
        found = shutil.which(candidate)
        if found:
            return found
    return None


def _build_args(tracer: str, target: str, max_hops: int) -> List[str]:
    """Build subprocess argument list for the detected tracer."""
    name = tracer.split("/")[-1].lower()
    if "tracert" in name:
        return [tracer, "-h", str(max_hops), target]
    if "tracepath" in name:
        return [tracer, "-n", target]
    # Default: traceroute
    return [tracer, "-m", str(max_hops), "-n", target]


def _parse_hops(output: str) -> List[RouteHop]:
    """Parse traceroute text output into RouteHop objects."""
    hops: List[RouteHop] = []
    for line in output.splitlines():
        m = _HOP_RE.match(line)
        if not m:
            continue
        hop_num = int(m.group(1))
        if m.group(2):  # timeout (*)
            hops.append(RouteHop(hop=hop_num, address=None, rtt_ms=None))
        elif m.group(3):
            hops.append(RouteHop(hop=hop_num, address=m.group(3), rtt_ms=float(m.group(4))))
    return hops


def run_route_diagnostics(target: str, max_hops: int = 20) -> RouteResult:
    """
    Run traceroute/tracepath against target if available.

    Never raises — returns RouteResult with supported=False if unavailable.

    Args:
        target: Hostname or IP to trace.
        max_hops: Maximum TTL / hop count.

    Returns:
        RouteResult with hops, raw_output, and limitation notes.
    """
    tracer = _find_tracer()
    if not tracer:
        logger.info("No traceroute utility found on this platform")
        return RouteResult(
            target=target,
            supported=False,
            error_detail="No traceroute/tracepath utility found on this system.",
        )

    args = _build_args(tracer, target, max_hops)
    logger.info("Running route diagnostics: %s", " ".join(args))

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=settings.route_timeout,
            shell=False,
        )
        raw = result.stdout or result.stderr or ""
        hops = _parse_hops(raw)
        logger.info("Route diagnostics completed: %d hops discovered", len(hops))
        return RouteResult(
            target=target,
            supported=True,
            hops=hops,
            raw_output=raw[:4096],  # cap size
        )
    except subprocess.TimeoutExpired:
        logger.warning("Route diagnostics timed out for %s", target)
        return RouteResult(
            target=target,
            supported=True,
            error_detail=f"Route diagnostics timed out after {settings.route_timeout}s.",
        )
    except FileNotFoundError:
        return RouteResult(
            target=target,
            supported=False,
            error_detail="Traceroute executable not found.",
        )
    except Exception as exc:
        logger.error("Route diagnostics error for %s: %s", target, exc)
        return RouteResult(
            target=target,
            supported=False,
            error_detail="Route diagnostics failed with an unexpected error.",
        )
