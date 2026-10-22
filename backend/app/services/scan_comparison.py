"""NetScope — scan comparison service."""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

from app.models.scan import Scan, ScanStatus
from app.schemas.scans import ComparisonResult, PortChange

logger = logging.getLogger(__name__)


def compare_scans(baseline: Scan, current: Scan) -> ComparisonResult:
    """
    Compare two Scan records and identify port-state and version changes.

    Args:
        baseline: The earlier (reference) scan.
        current: The later (comparison) scan.

    Returns:
        ComparisonResult with change lists and comparability assessment.
    """
    # ── Guard rails ──────────────────────────────────────────────────────────
    if baseline.status != ScanStatus.COMPLETED:
        return ComparisonResult(
            baseline_scan_id=baseline.id,
            current_scan_id=current.id,
            target=baseline.target,
            comparable=False,
            reason=(
                f"Baseline scan (id={baseline.id}) did not complete successfully "
                f"(status={baseline.status}). Cannot draw conclusions about changes."
            ),
        )

    if current.status != ScanStatus.COMPLETED:
        return ComparisonResult(
            baseline_scan_id=baseline.id,
            current_scan_id=current.id,
            target=current.target,
            comparable=False,
            reason=(
                f"Current scan (id={current.id}) did not complete successfully "
                f"(status={current.status})."
            ),
        )

    if baseline.target.lower() != current.target.lower():
        return ComparisonResult(
            baseline_scan_id=baseline.id,
            current_scan_id=current.id,
            target=baseline.target,
            comparable=False,
            reason="Scans cover different targets — comparison would be misleading.",
        )

    # ── Build port-state maps ────────────────────────────────────────────────
    def _port_map(scan: Scan) -> Dict[Tuple[int, str], str]:
        """Return {(port, protocol): state} for open findings."""
        m: Dict[Tuple[int, str], str] = {}
        for f in scan.findings:
            if f.port is not None and f.protocol:
                m[(f.port, f.protocol)] = f.state or "unknown"
        return m

    def _version_map(scan: Scan) -> Dict[Tuple[int, str], str]:
        """Return {(port, protocol): version} for open findings."""
        m: Dict[Tuple[int, str], str] = {}
        for f in scan.findings:
            if f.port is not None and f.protocol:
                m[(f.port, f.protocol)] = f.version or ""
        return m

    baseline_ports = _port_map(baseline)
    current_ports = _port_map(current)
    baseline_versions = _version_map(baseline)
    current_versions = _version_map(current)

    new_open: List[PortChange] = []
    closed: List[PortChange] = []
    version_changes: List[PortChange] = []

    all_keys = set(baseline_ports) | set(current_ports)

    for (port, proto) in sorted(all_keys):
        b_state = baseline_ports.get((port, proto))
        c_state = current_ports.get((port, proto))

        # Newly open port
        if b_state != "open" and c_state == "open":
            new_open.append(PortChange(
                port=port, protocol=proto, change_type="new_open",
                baseline_value=b_state or "not observed",
                current_value="open",
            ))

        # Port no longer open
        elif b_state == "open" and c_state != "open":
            closed.append(PortChange(
                port=port, protocol=proto, change_type="now_closed",
                baseline_value="open",
                current_value=c_state or "not observed",
            ))

        # Version changed (only for still-open ports)
        if b_state == "open" and c_state == "open":
            bv = baseline_versions.get((port, proto), "")
            cv = current_versions.get((port, proto), "")
            if bv != cv and (bv or cv):
                version_changes.append(PortChange(
                    port=port, protocol=proto, change_type="version_changed",
                    baseline_value=bv or "(unknown)",
                    current_value=cv or "(unknown)",
                ))

    logger.info(
        "Comparison %s vs %s: %d new, %d closed, %d version changes",
        baseline.id, current.id,
        len(new_open), len(closed), len(version_changes),
    )

    return ComparisonResult(
        baseline_scan_id=baseline.id,
        current_scan_id=current.id,
        target=baseline.target,
        comparable=True,
        new_open_ports=new_open,
        closed_ports=closed,
        version_changes=version_changes,
    )
