"""NetScope — unit tests for allowlist enforcement."""
from __future__ import annotations

import pytest
from unittest.mock import patch

from app.security.allowlist import validate_target_allowed, AllowlistError


# ── Helpers ────────────────────────────────────────────────────────────────

PRIVATE_CIDR_SETTINGS = "127.0.0.1,::1,localhost,10.0.0.0/8,192.168.0.0/16"


def _set_allowlist(monkeypatch, targets: str):
    monkeypatch.setattr("app.security.allowlist.settings.allowed_targets", targets)


# ── IP address tests ───────────────────────────────────────────────────────

def test_allowed_loopback_ip(monkeypatch):
    _set_allowlist(monkeypatch, PRIVATE_CIDR_SETTINGS)
    assert validate_target_allowed("127.0.0.1") == "127.0.0.1"


def test_allowed_private_ip_in_cidr(monkeypatch):
    _set_allowlist(monkeypatch, PRIVATE_CIDR_SETTINGS)
    assert validate_target_allowed("10.10.20.30") == "10.10.20.30"


def test_allowed_192168_ip(monkeypatch):
    _set_allowlist(monkeypatch, PRIVATE_CIDR_SETTINGS)
    assert validate_target_allowed("192.168.1.1") == "192.168.1.1"


def test_blocked_public_ip(monkeypatch):
    _set_allowlist(monkeypatch, PRIVATE_CIDR_SETTINGS)
    with pytest.raises(AllowlistError, match="authorised scan scope"):
        validate_target_allowed("8.8.8.8")


def test_blocked_public_ip_different_range(monkeypatch):
    _set_allowlist(monkeypatch, PRIVATE_CIDR_SETTINGS)
    with pytest.raises(AllowlistError):
        validate_target_allowed("1.1.1.1")


# ── Hostname tests ──────────────────────────────────────────────────────────

def test_allowed_explicit_hostname(monkeypatch):
    _set_allowlist(monkeypatch, "scanme.nmap.org,127.0.0.1")
    assert validate_target_allowed("scanme.nmap.org") == "scanme.nmap.org"


def test_localhost_hostname(monkeypatch):
    _set_allowlist(monkeypatch, PRIVATE_CIDR_SETTINGS)
    # localhost resolves to 127.0.0.1 — should be in allowlist
    assert validate_target_allowed("localhost") == "localhost"


# ── Edge cases ─────────────────────────────────────────────────────────────

def test_empty_target_raises(monkeypatch):
    _set_allowlist(monkeypatch, PRIVATE_CIDR_SETTINGS)
    with pytest.raises(ValueError, match="empty"):
        validate_target_allowed("")


def test_too_long_target_raises(monkeypatch):
    _set_allowlist(monkeypatch, PRIVATE_CIDR_SETTINGS)
    with pytest.raises(ValueError, match="maximum length"):
        validate_target_allowed("a" * 254)


def test_strips_whitespace(monkeypatch):
    _set_allowlist(monkeypatch, PRIVATE_CIDR_SETTINGS)
    assert validate_target_allowed("  127.0.0.1  ") == "127.0.0.1"


def test_empty_allowlist_blocks_everything(monkeypatch):
    _set_allowlist(monkeypatch, "")
    with pytest.raises(AllowlistError):
        validate_target_allowed("127.0.0.1")
