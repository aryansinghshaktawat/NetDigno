"""NetDigno — unit tests for scan database repository persistence."""
import pytest
from app.models.base import create_tables, get_db
from app.models.scan import ScanProfile, ScanStatus
from app.repositories.scan_repository import (
    create_scan,
    complete_scan,
    get_scan_by_id,
    list_scans,
    update_scan_running,
)


@pytest.fixture(autouse=True)
async def init_test_db():
    await create_tables()
    yield


@pytest.mark.anyio
async def test_create_and_retrieve_scan():
    async for db in get_db():
        scan = await create_scan(db, target="127.0.0.1", profile=ScanProfile.QUICK)
        assert scan.id is not None
        assert scan.target == "127.0.0.1"
        assert scan.profile == ScanProfile.QUICK
        assert scan.status == ScanStatus.PENDING

        retrieved = await get_scan_by_id(db, scan.id)
        assert retrieved is not None
        assert retrieved.id == scan.id
        break


@pytest.mark.anyio
async def test_update_and_complete_scan():
    async for db in get_db():
        scan = await create_scan(db, target="192.168.1.1", profile=ScanProfile.SERVICE)
        running = await update_scan_running(db, scan)
        assert running.status == ScanStatus.RUNNING

        await complete_scan(
            db,
            scan,
            status=ScanStatus.COMPLETED,
            findings_data=[
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "version": "nginx 1.18",
                    "cve_refs": ["CVE-2021-23017"],
                    "evidence": "80/tcp open http",
                }
            ],
            duration_seconds=1.25,
            nmap_command="nmap -sV -p 80 192.168.1.1",
            exit_code=0,
        )

        # Retrieve with eager findings loading
        retrieved = await get_scan_by_id(db, scan.id)
        assert retrieved is not None
        assert retrieved.status == ScanStatus.COMPLETED
        assert retrieved.duration_seconds == 1.25
        assert len(retrieved.findings) == 1
        assert retrieved.findings[0].port == 80
        assert retrieved.findings[0].service == "http"
        break


@pytest.mark.anyio
async def test_list_scans_pagination_and_filter():
    async for db in get_db():
        await create_scan(db, target="10.0.0.1", profile=ScanProfile.QUICK)
        await create_scan(db, target="10.0.0.2", profile=ScanProfile.VULN)

        total, items = await list_scans(db, target="10.0.0.1", page=1, page_size=10)
        assert total >= 1
        assert any(item.target == "10.0.0.1" for item in items)
        break
