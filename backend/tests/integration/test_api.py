"""NetScope — integration tests for diagnostics and scans API endpoints."""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, MagicMock

from app.main import app
from app.models.base import create_tables


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
async def setup_db():
    await create_tables()
    yield


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


# ── Health ─────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_health_endpoint(client):
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "nmap_available" in data


# ── DNS diagnostics ────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_dns_valid_hostname(client):
    with patch("app.api.v1.diagnostics.resolve_dns") as mock_dns:
        mock_dns.return_value = MagicMock(
            hostname="localhost",
            ipv4_addresses=["127.0.0.1"],
            ipv6_addresses=[],
            resolution_success=True,
            resolution_duration_ms=1.5,
            error_category=None,
            error_detail=None,
            note="test",
        )
        response = await client.post("/api/v1/diagnostics/dns", json={"hostname": "localhost"})
    assert response.status_code == 200


@pytest.mark.anyio
async def test_dns_empty_hostname(client):
    response = await client.post("/api/v1/diagnostics/dns", json={"hostname": ""})
    assert response.status_code == 422


@pytest.mark.anyio
async def test_dns_missing_body(client):
    response = await client.post("/api/v1/diagnostics/dns", json={})
    assert response.status_code == 422


# ── TCP diagnostics ────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_tcp_invalid_port(client):
    response = await client.post(
        "/api/v1/diagnostics/tcp",
        json={"target": "127.0.0.1", "port": 99999}
    )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_tcp_port_zero(client):
    response = await client.post(
        "/api/v1/diagnostics/tcp",
        json={"target": "127.0.0.1", "port": 0}
    )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_tcp_blocked_target(client):
    with patch("app.api.v1.diagnostics.validate_target_allowed") as mock_allow:
        from app.security.allowlist import AllowlistError
        mock_allow.side_effect = AllowlistError("not allowed")
        response = await client.post(
            "/api/v1/diagnostics/tcp",
            json={"target": "8.8.8.8", "port": 80}
        )
    assert response.status_code == 403


# ── Scans ──────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_scan_missing_authorization(client):
    response = await client.post("/api/v1/scans", json={
        "target": "127.0.0.1",
        "profile": "quick",
        "authorized": False,
    })
    assert response.status_code == 422


@pytest.mark.anyio
async def test_scan_empty_target(client):
    response = await client.post("/api/v1/scans", json={
        "target": "",
        "profile": "quick",
        "authorized": True,
    })
    assert response.status_code == 422


@pytest.mark.anyio
async def test_scan_invalid_profile(client):
    response = await client.post("/api/v1/scans", json={
        "target": "127.0.0.1",
        "profile": "hyperdeepultramax",
        "authorized": True,
    })
    assert response.status_code == 422


@pytest.mark.anyio
async def test_list_scans_empty_state(client):
    response = await client.get("/api/v1/scans")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data


@pytest.mark.anyio
async def test_get_nonexistent_scan(client):
    response = await client.get("/api/v1/scans/nonexistent-scan-id")
    assert response.status_code == 404


@pytest.mark.anyio
async def test_compare_nonexistent_baseline(client):
    response = await client.get(
        "/api/v1/scans/compare",
        params={"baseline_id": "fake-id-1", "current_id": "fake-id-2"}
    )
    assert response.status_code == 404
