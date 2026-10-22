"""NetScope — unit tests for scan comparison service."""
from __future__ import annotations

import pytest
from datetime import datetime
from unittest.mock import MagicMock

from app.models.scan import Scan, ScanStatus
from app.services.scan_comparison import compare_scans


def _make_scan(id: str, target: str, status: str, findings: list) -> Scan:
    scan = MagicMock(spec=Scan)
    scan.id = id
    scan.target = target
    scan.status = status
    scan.findings = findings
    return scan


def _make_finding(port: int, protocol: str, state: str, version: str = ""):
    f = MagicMock()
    f.port = port
    f.protocol = protocol
    f.state = state
    f.version = version
    return f


# ── Comparability guards ───────────────────────────────────────────────────

def test_incomplete_baseline_not_comparable():
    baseline = _make_scan("b1", "127.0.0.1", ScanStatus.FAILED, [])
    current = _make_scan("c1", "127.0.0.1", ScanStatus.COMPLETED, [])
    result = compare_scans(baseline, current)
    assert result.comparable is False
    assert "baseline" in result.reason.lower()


def test_incomplete_current_not_comparable():
    baseline = _make_scan("b1", "127.0.0.1", ScanStatus.COMPLETED, [])
    current = _make_scan("c1", "127.0.0.1", ScanStatus.TIMEOUT, [])
    result = compare_scans(baseline, current)
    assert result.comparable is False


def test_different_targets_not_comparable():
    baseline = _make_scan("b1", "127.0.0.1", ScanStatus.COMPLETED, [])
    current = _make_scan("c1", "10.0.0.1", ScanStatus.COMPLETED, [])
    result = compare_scans(baseline, current)
    assert result.comparable is False
    assert "targets" in result.reason.lower()


# ── Change detection ───────────────────────────────────────────────────────

def test_new_open_port_detected():
    baseline = _make_scan("b1", "127.0.0.1", ScanStatus.COMPLETED, [
        _make_finding(22, "tcp", "open"),
    ])
    current = _make_scan("c1", "127.0.0.1", ScanStatus.COMPLETED, [
        _make_finding(22, "tcp", "open"),
        _make_finding(80, "tcp", "open"),  # new
    ])
    result = compare_scans(baseline, current)
    assert result.comparable is True
    assert len(result.new_open_ports) == 1
    assert result.new_open_ports[0].port == 80


def test_closed_port_detected():
    baseline = _make_scan("b1", "127.0.0.1", ScanStatus.COMPLETED, [
        _make_finding(22, "tcp", "open"),
        _make_finding(443, "tcp", "open"),
    ])
    current = _make_scan("c1", "127.0.0.1", ScanStatus.COMPLETED, [
        _make_finding(22, "tcp", "open"),
        # 443 now missing
    ])
    result = compare_scans(baseline, current)
    assert len(result.closed_ports) == 1
    assert result.closed_ports[0].port == 443


def test_version_change_detected():
    baseline = _make_scan("b1", "127.0.0.1", ScanStatus.COMPLETED, [
        _make_finding(80, "tcp", "open", version="Apache 2.4.41"),
    ])
    current = _make_scan("c1", "127.0.0.1", ScanStatus.COMPLETED, [
        _make_finding(80, "tcp", "open", version="Apache 2.4.54"),
    ])
    result = compare_scans(baseline, current)
    assert len(result.version_changes) == 1
    assert result.version_changes[0].baseline_value == "Apache 2.4.41"
    assert result.version_changes[0].current_value == "Apache 2.4.54"


def test_no_changes_returns_empty_lists():
    finding = _make_finding(22, "tcp", "open", version="OpenSSH 8.2")
    baseline = _make_scan("b1", "127.0.0.1", ScanStatus.COMPLETED, [finding])
    current = _make_scan("c1", "127.0.0.1", ScanStatus.COMPLETED, [
        _make_finding(22, "tcp", "open", version="OpenSSH 8.2"),
    ])
    result = compare_scans(baseline, current)
    assert result.comparable is True
    assert len(result.new_open_ports) == 0
    assert len(result.closed_ports) == 0
    assert len(result.version_changes) == 0
