"""NetDigno — Pydantic schemas for diagnostic endpoints."""
from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field, field_validator
import re


# ── Shared validator ─────────────────────────────────────────────────────────
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)


def _validate_target(v: str) -> str:
    v = v.strip()
    if not v:
        raise ValueError("Target must not be empty.")
    if len(v) > 253:
        raise ValueError("Target exceeds maximum length.")
    return v


# ── DNS ──────────────────────────────────────────────────────────────────────

class DnsRequest(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=253, examples=["scanme.nmap.org"])

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        return _validate_target(v)


class DnsResult(BaseModel):
    hostname: str
    ipv4_addresses: List[str] = []
    ipv6_addresses: List[str] = []
    resolution_success: bool
    resolution_duration_ms: float
    error_category: Optional[str] = None
    error_detail: Optional[str] = None
    note: str = (
        "DNS resolution confirms the hostname maps to the listed addresses "
        "at the time of the query. It does not confirm that a service is "
        "reachable or that the host is online."
    )


# ── TCP ──────────────────────────────────────────────────────────────────────

class TcpRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253, examples=["127.0.0.1"])
    port: int = Field(..., ge=1, le=65535, examples=[80])
    timeout_seconds: float = Field(default=5.0, ge=0.5, le=30.0)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _validate_target(v)


class TcpResult(BaseModel):
    target: str
    port: int
    success: bool
    connection_duration_ms: Optional[float] = None
    timed_out: bool = False
    error_detail: Optional[str] = None
    note: str = (
        "A successful TCP connection confirms a connection was established "
        "at this moment on this port. A failure may result from filtering, "
        "routing, service availability, or network conditions — it does not "
        "necessarily mean the entire host is offline."
    )


# ── Route ────────────────────────────────────────────────────────────────────

class RouteRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253, examples=["8.8.8.8"])
    max_hops: int = Field(default=20, ge=1, le=64)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _validate_target(v)


class RouteHop(BaseModel):
    hop: int
    address: Optional[str] = None
    rtt_ms: Optional[float] = None


class RouteResult(BaseModel):
    target: str
    supported: bool
    hops: List[RouteHop] = []
    raw_output: Optional[str] = None
    error_detail: Optional[str] = None
    note: str = (
        "Route diagnostics show the network path observed at this time. "
        "ICMP filtering may cause hops to appear missing. Results vary "
        "by network conditions and do not confirm end-to-end reachability."
    )
