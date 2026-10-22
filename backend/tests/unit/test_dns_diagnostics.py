"""NetScope — unit tests for DNS diagnostics service."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
import dns.resolver
import dns.exception
import pytest

from app.services.dns_diagnostics import resolve_dns


def test_dns_resolution_success():
    mock_rdata_a = MagicMock()
    mock_rdata_a.address = "127.0.0.1"
    mock_rdata_aaaa = MagicMock()
    mock_rdata_aaaa.address = "::1"

    with patch("dns.resolver.Resolver") as mock_resolver_cls:
        resolver_inst = MagicMock()
        resolver_inst.resolve.side_effect = lambda host, rtype: (
            [mock_rdata_a] if rtype == "A" else [mock_rdata_aaaa]
        )
        mock_resolver_cls.return_value = resolver_inst

        result = resolve_dns("localhost")
        assert result.resolution_success is True
        assert "127.0.0.1" in result.ipv4_addresses
        assert "::1" in result.ipv6_addresses
        assert result.error_category is None
        assert result.error_detail is None
        assert result.resolution_duration_ms >= 0


def test_dns_resolution_nxdomain():
    with patch("dns.resolver.Resolver") as mock_resolver_cls:
        resolver_inst = MagicMock()
        resolver_inst.resolve.side_effect = dns.resolver.NXDOMAIN()
        mock_resolver_cls.return_value = resolver_inst

        result = resolve_dns("nonexistent.example.internal")
        assert result.resolution_success is False
        assert result.ipv4_addresses == []
        assert result.ipv6_addresses == []
        assert result.error_category == "NXDOMAIN"
        assert result.error_detail is not None


def test_dns_resolution_timeout():
    with patch("dns.resolver.Resolver") as mock_resolver_cls:
        resolver_inst = MagicMock()
        resolver_inst.resolve.side_effect = dns.exception.Timeout()
        mock_resolver_cls.return_value = resolver_inst

        result = resolve_dns("slow.example.com")
        assert result.resolution_success is False
        assert result.error_category == "TIMEOUT"


def test_dns_resolution_system_error():
    with patch("dns.resolver.Resolver") as mock_resolver_cls:
        resolver_inst = MagicMock()
        resolver_inst.resolve.side_effect = RuntimeError("DNS socket failure")
        mock_resolver_cls.return_value = resolver_inst

        result = resolve_dns("test.local")
        assert result.resolution_success is False
        assert result.error_category == "UNKNOWN"
