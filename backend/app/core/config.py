"""NetDigno — centralised configuration via environment variables."""
from __future__ import annotations

from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── Application ────────────────────────────────────────────────────────
    app_name: str = "NetDigno"

    # ── Server ─────────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"

    # ── CORS ───────────────────────────────────────────────────────────────
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    # ── Database ───────────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./netdigno.db"

    # ── Scan timeouts (seconds) ────────────────────────────────────────────
    quick_scan_timeout: int = 120
    service_scan_timeout: int = 300
    vuln_scan_timeout: int = 600

    # ── Diagnostics timeouts ───────────────────────────────────────────────
    dns_timeout: float = 5.0
    tcp_timeout: float = 10.0
    route_timeout: int = 30

    # ── Target allowlist ───────────────────────────────────────────────────
    # Comma-separated list of allowed IPs, CIDRs, and hostnames.
    # Default: localhost + well-known test targets.
    # Set ALLOWED_TARGETS="" to disable scanning (safe-by-default).
    allowed_targets: str = (
        "127.0.0.1,::1,localhost,"
        "scanme.nmap.org,"
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    )

    # ── Rate limits ────────────────────────────────────────────────────────
    scan_rate_limit: str = "6/minute"
    diagnostics_rate_limit: str = "30/minute"

    # ── Concurrency ────────────────────────────────────────────────────────
    max_concurrent_scans: int = 3

    # ── Nmap ──────────────────────────────────────────────────────────────
    nmap_path: str = "nmap"


settings = Settings()
