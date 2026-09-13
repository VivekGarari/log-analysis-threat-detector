from datetime import datetime, timezone
from pathlib import Path

import pytest

from threat_detector.normalization.windows_security import (
    normalize_windows_security_event,
)
from threat_detector.parsers.windows_security import (
    WindowsSecurityAuthEvent,
    parse_event,
)


FIXTURES = Path(__file__).parents[2] / "data" / "fixtures" / "windows"


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_normalize_successful_windows_security_logon():
    raw = read_fixture("security_4624.xml")
    event = parse_event(raw)

    assert event is not None
    normalized = normalize_windows_security_event(event)

    assert normalized.timestamp == datetime(2026, 9, 2, 12, 34, 56, 123456, tzinfo=timezone.utc)
    assert normalized.timestamp.tzinfo is timezone.utc
    assert normalized.event_type == "authentication_success"
    assert normalized.success is True
    assert normalized.source == "windows_security"
    assert normalized.service is None
    assert normalized.hostname == "WIN-AUTH-01.example.test"
    assert normalized.username == "alice"
    assert normalized.source_ip == "203.0.113.50"
    assert normalized.source_port == 49832
    assert normalized.raw == raw
    assert normalized.http_path is None


def test_normalize_failed_windows_security_logon_with_missing_network_values():
    raw = read_fixture("security_4625.xml")
    event = parse_event(raw)

    assert event is not None
    normalized = normalize_windows_security_event(event)

    assert normalized.timestamp == datetime(2026, 9, 2, 12, 35, 1, tzinfo=timezone.utc)
    assert normalized.event_type == "authentication_failure"
    assert normalized.success is False
    assert normalized.hostname == "WIN-AUTH-01.example.test"
    assert normalized.username == "alice"
    assert normalized.source_ip is None
    assert normalized.source_port is None
    assert normalized.http_path is None


def test_normalize_rejects_unsupported_event_id():
    event = WindowsSecurityAuthEvent(
        timestamp="2026-09-02T12:34:56Z",
        hostname="WIN-AUTH-01",
        username="alice",
        source_ip=None,
        source_port=None,
        event_id=4634,
        raw="raw event",
    )

    with pytest.raises(ValueError, match="Unsupported Windows Security event ID"):
        normalize_windows_security_event(event)


def test_normalize_rejects_naive_windows_timestamp():
    event = WindowsSecurityAuthEvent(
        timestamp="2026-09-02T12:34:56",
        hostname="WIN-AUTH-01",
        username="alice",
        source_ip=None,
        source_port=None,
        event_id=4625,
        raw="raw event",
    )

    with pytest.raises(ValueError, match="must be timezone-aware"):
        normalize_windows_security_event(event)
