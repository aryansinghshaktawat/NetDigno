"""NetDigno — security: target allowlist enforcement."""
from __future__ import annotations

import ipaddress
import logging
import socket
from typing import List, Tuple

from app.core.config import settings

logger = logging.getLogger(__name__)


class AllowlistError(Exception):
    """Raised when a target is not on the allowlist or targets prohibited ranges."""


PROHIBITED_NETWORKS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("169.254.0.0/16"),  # IPv4 Link-Local / Cloud Metadata (AWS, GCP, Azure)
    ipaddress.ip_network("fe80::/10"),       # IPv6 Link-Local
    ipaddress.ip_network("224.0.0.0/4"),     # IPv4 Multicast
    ipaddress.ip_network("ff00::/8"),        # IPv6 Multicast
    ipaddress.ip_network("0.0.0.0/8"),       # Current local network
]


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
        return list({str(r[4][0]) for r in results})
    except socket.gaierror:
        return []


def _is_prohibited_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address belongs to any prohibited destination network."""
    for network in PROHIBITED_NETWORKS:
        if ip in network:
            return True
    return False


def validate_target_allowed(target: str) -> str:
    """
    Validate that the target is permitted and not in prohibited ranges.

    Args:
        target: Hostname or IP address string.

    Returns:
        Normalised target string.

    Raises:
        AllowlistError: If the target is not permitted or in prohibited range.
        ValueError: If the target string is malformed or empty.
    """
    target = target.strip().lower()
    if not target:
        raise ValueError("Target must not be empty.")

    if len(target) > 253:
        raise ValueError("Target exceeds maximum length.")

    # ── 1. Direct IP check ──────────────────────────────────────────────────
    try:
        addr = ipaddress.ip_address(target)
        if _is_prohibited_ip(addr):
            raise AllowlistError(
                f"Target '{target}' is a prohibited destination (link-local or cloud metadata endpoint)."
            )

        allowed_hostnames, allowed_networks = _parse_allowlist()
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

    allowed_hostnames, allowed_networks = _parse_allowlist()

    # ── 2. Hostname resolution & DNS Rebinding Check ────────────────────────
    resolved_ips = _resolve_to_ips(target)
    if not resolved_ips:
        # If hostname is explicitly allowed (e.g. mock tests without network DNS)
        if target in allowed_hostnames:
            logger.debug("Target %s allowed via explicit hostname list (unresolved)", target)
            return target
        raise AllowlistError(
            f"Could not resolve hostname '{target}'. "
            "Ensure the hostname is valid and the target is in the authorised scope."
        )

    # Check for DNS rebinding to prohibited destinations
    for ip_str in resolved_ips:
        try:
            addr = ipaddress.ip_address(ip_str)
            if _is_prohibited_ip(addr):
                raise AllowlistError(
                    f"Target '{target}' resolves to a prohibited destination ({ip_str})."
                )
        except ValueError:
            continue

    # ── 3. Hostname in explicit allowed list ─────────────────────────────────
    if target in allowed_hostnames:
        logger.debug("Target %s allowed via hostname list", target)
        return target

    # ── 4. Check if resolved IPs fall into allowed networks ─────────────────
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
