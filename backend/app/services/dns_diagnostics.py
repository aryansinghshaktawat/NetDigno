"""NetScope — DNS diagnostics service using dnspython."""
from __future__ import annotations

import logging
import socket
import time
from typing import List, Tuple

import dns.resolver
import dns.exception

from app.core.config import settings
from app.schemas.diagnostics import DnsResult

logger = logging.getLogger(__name__)


def _classify_dns_error(exc: Exception) -> Tuple[str, str]:
    """Return (category, detail) for a DNS exception."""
    if isinstance(exc, dns.resolver.NXDOMAIN):
        return "NXDOMAIN", "The hostname does not exist in DNS."
    if isinstance(exc, dns.resolver.NoAnswer):
        return "NO_ANSWER", "The DNS server returned no answer for the requested record type."
    if isinstance(exc, dns.resolver.NoNameservers):
        return "NO_NAMESERVERS", "No nameservers could be reached for this domain."
    if isinstance(exc, dns.exception.Timeout):
        return "TIMEOUT", f"DNS query timed out after {settings.dns_timeout}s."
    if hasattr(dns.resolver, "NotAbsolute") and isinstance(exc, dns.resolver.NotAbsolute):
        return "INVALID_HOSTNAME", "The hostname is not a valid absolute domain name."
    return "UNKNOWN", str(exc)


def resolve_dns(hostname: str) -> DnsResult:
    """
    Perform A and AAAA lookups for a hostname.

    Args:
        hostname: The hostname to resolve.

    Returns:
        DnsResult with resolved addresses, timing, and any error category.
    """
    logger.info("DNS lookup: %s", hostname)
    resolver = dns.resolver.Resolver()
    resolver.lifetime = settings.dns_timeout

    ipv4: List[str] = []
    ipv6: List[str] = []
    error_category: str | None = None
    error_detail: str | None = None

    start = time.perf_counter()

    # ── A record ────────────────────────────────────────────────────────────
    try:
        answers = resolver.resolve(hostname, "A")
        ipv4 = [rdata.address for rdata in answers]
    except Exception as exc:
        category, detail = _classify_dns_error(exc)
        error_category = category
        error_detail = detail
        logger.warning("DNS A lookup failed for %s: %s — %s", hostname, category, detail)

    # ── AAAA record (best effort) ────────────────────────────────────────────
    if error_category is None or error_category == "NO_ANSWER":
        try:
            answers6 = resolver.resolve(hostname, "AAAA")
            ipv6 = [rdata.address for rdata in answers6]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass  # IPv6 absence is not an error
        except Exception as exc:
            logger.debug("DNS AAAA lookup failed for %s: %s", hostname, exc)

    elapsed_ms = (time.perf_counter() - start) * 1000
    success = bool(ipv4 or ipv6)

    logger.info(
        "DNS result for %s: success=%s, ipv4=%s, ipv6=%s, elapsed=%.1fms",
        hostname, success, ipv4, ipv6, elapsed_ms,
    )

    return DnsResult(
        hostname=hostname,
        ipv4_addresses=ipv4,
        ipv6_addresses=ipv6,
        resolution_success=success,
        resolution_duration_ms=round(elapsed_ms, 2),
        error_category=error_category if not success else None,
        error_detail=error_detail if not success else None,
    )
