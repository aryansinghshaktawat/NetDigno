"""NetScope — unit tests for TCP diagnostics service."""
from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch
import pytest

from app.services.tcp_diagnostics import check_tcp


def test_tcp_connection_success():
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 0
    with patch("socket.create_connection", return_value=mock_sock):
        result = check_tcp("127.0.0.1", 80, timeout_seconds=2.0)
        assert result.success is True
        assert result.timed_out is False
        assert result.error_detail is None
        assert result.connection_duration_ms is not None
        assert result.connection_duration_ms >= 0


def test_tcp_connection_timeout():
    with patch("socket.create_connection", side_effect=socket.timeout("timed out")):
        result = check_tcp("192.168.1.200", 443, timeout_seconds=1.0)
        assert result.success is False
        assert result.timed_out is True
        assert "timed out" in (result.error_detail or "").lower()


def test_tcp_connection_refused():
    with patch("socket.create_connection", side_effect=ConnectionRefusedError("Connection refused")):
        result = check_tcp("127.0.0.1", 54321, timeout_seconds=1.0)
        assert result.success is False
        assert result.timed_out is False
        assert "refused" in (result.error_detail or "").lower()


def test_tcp_connection_os_error():
    with patch("socket.create_connection", side_effect=OSError("Network is unreachable")):
        result = check_tcp("10.255.255.1", 80, timeout_seconds=1.0)
        assert result.success is False
        assert result.timed_out is False
        assert "unreachable" in (result.error_detail or "").lower()
