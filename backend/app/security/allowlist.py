"""NetScope — security: target allowlist enforcement."""
from __future__ import annotations

import ipaddress
import logging
import socket
from typing import List, Tuple

from app.core.config import settings

logger = logging.getLogger(__name__)


class AllowlistError(Exception):
    """Raised when a target is not on the allowlist."""


def _parse_allowlist() -> Tuple[List[str], List[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    """Parse ALLOWED_TARGETS into hostnames and CIDR networks."""
    hostnames: List[str] = []
    networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

    for entry in settings.allowed_targets.split(","):
        entry = entry.strip().lower()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            # Not an IP/CIDR — treat as hostname
            hostnames.append(entry)

    return hostnames, networks


def _resolve_to_ips(target: str) -> List[str]:
    """Resolve a hostname to its IP addresses. Returns empty list on failure."""
    try:
        results = socket.getaddrinfo(target, None)
        return list({r[4][0] for r in results})
    except socket.gaierror:
        return []


def validate_target_allowed(target: str) -> str:
    """
    Validate that the target is on the configured allowlist.

    Args:
        target: Hostname or IP address string.

    Returns:
        Normalised target string.

    Raises:
        AllowlistError: If the target is not permitted.
        ValueError: If the target string is malformed.
    """
    target = target.strip().lower()
    if not target:
        raise ValueError("Target must not be empty.")

    # Quick length/character guard
    if len(target) > 253:
        raise ValueError("Target exceeds maximum length.")

    allowed_hostnames, allowed_networks = _parse_allowlist()

    # ── 1. Direct IP match ──────────────────────────────────────────────────
    try:
        addr = ipaddress.ip_address(target)
        for network in allowed_networks:
            if addr in network:
                logger.debug("Target %s allowed via CIDR %s", target, network)
                return target
        raise AllowlistError(
            f"Target '{target}' is not in the authorised scan scope. "
            "Adjust ALLOWED_TARGETS to include this address."
        )
    except ValueError:
        pass  # Not a bare IP address — proceed to hostname check

    # ── 2. Hostname in explicit list ────────────────────────────────────────
    if target in allowed_hostnames:
        logger.debug("Target %s allowed via hostname list", target)
        return target

    # ── 3. Resolve hostname and check resolved IPs ──────────────────────────
    resolved_ips = _resolve_to_ips(target)
    if not resolved_ips:
        raise AllowlistError(
            f"Could not resolve hostname '{target}'. "
            "Ensure the hostname is valid and the target is in the authorised scope."
        )

    for ip_str in resolved_ips:
        try:
            addr = ipaddress.ip_address(ip_str)
            for network in allowed_networks:
                if addr in network:
                    logger.debug(
                        "Target %s allowed — resolved IP %s is in CIDR %s",
                        target, ip_str, network,
                    )
                    return target
        except ValueError:
            continue

    raise AllowlistError(
        f"Target '{target}' resolves to addresses outside the authorised scan scope. "
        "Contact the administrator to expand the allowed target list."
    )
