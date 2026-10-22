"""NetDigno — unit tests for Nmap XML parser."""
from __future__ import annotations

import pytest

from app.services.nmap_service import _parse_nmap_xml, _extract_cves


# ── CVE extraction ─────────────────────────────────────────────────────────

def test_extract_cves_basic():
    text = "This affects CVE-2021-44228 and CVE-2019-0708"
    result = _extract_cves(text)
    assert "CVE-2021-44228" in result
    assert "CVE-2019-0708" in result


def test_extract_cves_deduplication():
    text = "CVE-2021-44228 CVE-2021-44228"
    result = _extract_cves(text)
    assert result.count("CVE-2021-44228") == 1


def test_extract_cves_empty():
    assert _extract_cves("") == []


# ── XML parsing ────────────────────────────────────────────────────────────

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache" version="2.4.41" extrainfo="(Ubuntu)"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="closed" reason="reset"/>
        <service name="unknown"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

def test_parse_valid_xml():
    findings = _parse_nmap_xml(SAMPLE_XML)
    assert len(findings) == 3
    ports = {f["port"] for f in findings}
    assert 80 in ports
    assert 22 in ports


def test_parse_xml_open_state():
    findings = _parse_nmap_xml(SAMPLE_XML)
    open_ports = [f for f in findings if f["state"] == "open"]
    assert len(open_ports) == 2


def test_parse_xml_service_info():
    findings = _parse_nmap_xml(SAMPLE_XML)
    http = next(f for f in findings if f["port"] == 80)
    assert http["service"] == "http"
    assert "Apache" in http["version"]


def test_parse_xml_closed_port():
    findings = _parse_nmap_xml(SAMPLE_XML)
    closed = next(f for f in findings if f["port"] == 9999)
    assert closed["state"] == "closed"


def test_parse_empty_xml_returns_empty_list():
    assert _parse_nmap_xml("") == []


def test_parse_malformed_xml_returns_empty_list():
    assert _parse_nmap_xml("<broken xml <<") == []


def test_parse_no_ports_xml():
    xml = '<?xml version="1.0"?><nmaprun><host><ports></ports></host></nmaprun>'
    assert _parse_nmap_xml(xml) == []


def test_parse_xml_with_nse_cve():
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
        <script id="ssl-heartbleed" output="VULNERABLE: CVE-2014-0160"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    findings = _parse_nmap_xml(xml)
    assert len(findings) == 1
    assert findings[0]["cve_refs"] is not None
    assert "CVE-2014-0160" in findings[0]["cve_refs"]


def test_parse_xml_evidence_field():
    findings = _parse_nmap_xml(SAMPLE_XML)
    for f in findings:
        assert "evidence" in f
        assert f["evidence"]  # not empty
