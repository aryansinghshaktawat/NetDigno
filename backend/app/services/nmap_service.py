"""NetScope — Nmap execution and XML parsing service."""
from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from app.core.config import settings
from app.models.scan import ScanProfile

logger = logging.getLogger(__name__)


# ── Profile argument builder ──────────────────────────────────────────────────

PROFILE_ARGS: Dict[str, List[str]] = {
    ScanProfile.QUICK: [
        "-sT",          # TCP connect — no root required
        "-T4",          # Aggressive timing
        "-Pn",          # Skip ping
        "--top-ports", "100",
        "-oX", "-",     # XML output to stdout
    ],
    ScanProfile.SERVICE: [
        "-sT",
        "-sV",          # Service/version detection
        "-T4",
        "-Pn",
        "--top-ports", "1000",
        "-oX", "-",
    ],
    ScanProfile.VULN: [
        "-sT",
        "-sV",
        "-T4",
        "-Pn",
        "--script", "vuln,safe",
        "--script-timeout", "60s",
        "--top-ports", "1000",
        "-oX", "-",
    ],
}

PROFILE_TIMEOUTS: Dict[str, int] = {
    ScanProfile.QUICK: settings.quick_scan_timeout,
    ScanProfile.SERVICE: settings.service_scan_timeout,
    ScanProfile.VULN: settings.vuln_scan_timeout,
}


def nmap_available() -> bool:
    """Check whether nmap is installed."""
    nmap_path = shutil.which(settings.nmap_path)
    if not nmap_path:
        return False
    try:
        result = subprocess.run(
            [nmap_path, "--version"],
            capture_output=True, text=True, timeout=5, shell=False
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _extract_cves(text: str) -> List[str]:
    """Extract CVE identifiers from NSE output text."""
    found = re.findall(r"CVE-\d{4}-\d+", text, re.IGNORECASE)
    return list(sorted(set(f.upper() for f in found)))


def _parse_nmap_xml(xml_text: str) -> List[Dict]:
    """
    Parse Nmap XML output into a list of finding dicts.

    Returns empty list on any parse failure — never raises.
    """
    if not xml_text or not xml_text.strip():
        logger.warning("Empty Nmap XML output")
        return []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.error("Malformed Nmap XML: %s", exc)
        return []

    findings = []

    for host in root.findall("host"):
        for port_el in host.findall(".//port"):
            try:
                port_id = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")

                state_el = port_el.find("state")
                state = state_el.get("state", "unknown") if state_el is not None else "unknown"

                service_el = port_el.find("service")
                service_name = ""
                service_version = ""
                cpe_str = ""
                if service_el is not None:
                    service_name = service_el.get("name", "")
                    product = service_el.get("product", "")
                    version = service_el.get("version", "")
                    extra = service_el.get("extrainfo", "")
                    parts = [p for p in [product, version, extra] if p]
                    service_version = " ".join(parts)
                    cpe_el = service_el.find("cpe")
                    cpe_str = cpe_el.text if cpe_el is not None else ""

                # NSE script output
                nse_lines: List[str] = []
                cve_refs: List[str] = []
                for script_el in port_el.findall("script"):
                    script_out = script_el.get("output", "")
                    nse_lines.append(
                        f"{script_el.get('id', '')}: {script_out}"
                    )
                    cve_refs.extend(_extract_cves(script_out))

                nse_output = "\n".join(nse_lines) if nse_lines else None

                findings.append({
                    "port": port_id,
                    "protocol": protocol,
                    "state": state,
                    "service": service_name,
                    "version": service_version,
                    "cpe": cpe_str,
                    "nse_output": nse_output,
                    "cve_refs": list(set(cve_refs)) if cve_refs else None,
                    "evidence": (
                        f"Observed by Nmap {protocol.upper()} connect scan "
                        f"on port {port_id}/{protocol} — state reported as '{state}'."
                    ),
                })
            except Exception as exc:
                logger.warning("Error parsing port element: %s", exc)
                continue

    logger.info("Parsed %d findings from Nmap XML", len(findings))
    return findings


class NmapScanResult:
    """Container for a completed Nmap execution."""

    def __init__(
        self,
        command: List[str],
        exit_code: int,
        stdout: str,
        stderr: str,
        duration_seconds: float,
        findings: List[Dict],
        error_message: Optional[str] = None,
    ):
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_seconds = duration_seconds
        self.findings = findings
        self.error_message = error_message
        self.timed_out = False


def run_nmap_scan(target: str, profile: str) -> NmapScanResult:
    """
    Execute Nmap with a fixed profile-based argument set.

    Args:
        target: Validated, allowlisted target hostname or IP.
        profile: ScanProfile value (quick / service / vuln).

    Returns:
        NmapScanResult with parsed findings and execution metadata.

    Never exposes raw subprocess errors to callers. All errors are
    captured and returned in the error_message field.
    """
    nmap_path = shutil.which(settings.nmap_path) or settings.nmap_path

    profile_args = PROFILE_ARGS.get(profile, PROFILE_ARGS[ScanProfile.QUICK])
    timeout = PROFILE_TIMEOUTS.get(profile, settings.quick_scan_timeout)

    command = [nmap_path] + profile_args + [target]
    logger.info("Executing Nmap: profile=%s target=%s timeout=%ds", profile, target, timeout)

    start = datetime.utcnow()
    result = NmapScanResult(
        command=command,
        exit_code=-1,
        stdout="",
        stderr="",
        duration_seconds=0.0,
        findings=[],
    )

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        elapsed = (datetime.utcnow() - start).total_seconds()
        result.exit_code = proc.returncode
        result.stdout = proc.stdout or ""
        result.stderr = proc.stderr or ""
        result.duration_seconds = elapsed

        if proc.returncode not in (0, 1):
            # Nmap returns 1 for partial results (e.g., some hosts down)
            logger.warning(
                "Nmap returned exit code %d for %s: %s",
                proc.returncode, target, proc.stderr[:200],
            )
            result.error_message = f"Nmap exited with code {proc.returncode}."

        # Always attempt to parse XML even on non-zero exit
        result.findings = _parse_nmap_xml(result.stdout)
        logger.info(
            "Nmap scan complete: target=%s profile=%s exit=%d findings=%d duration=%.1fs",
            target, profile, proc.returncode, len(result.findings), elapsed,
        )

    except subprocess.TimeoutExpired:
        elapsed = (datetime.utcnow() - start).total_seconds()
        result.duration_seconds = elapsed
        result.timed_out = True
        result.error_message = f"Nmap scan timed out after {timeout}s."
        logger.warning("Nmap timed out for %s after %ds", target, timeout)

    except FileNotFoundError:
        result.error_message = "Nmap is not installed or not found in PATH."
        logger.error("Nmap not found at %s", nmap_path)

    except OSError as exc:
        result.error_message = f"OS error during Nmap execution: {exc.strerror}"
        logger.error("Nmap OS error for %s: %s", target, exc)

    return result
