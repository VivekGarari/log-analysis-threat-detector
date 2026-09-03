from datetime import datetime, timezone
from pathlib import Path

import pytest

from threat_detector.normalization.apache_access import normalize_apache_access_event
from threat_detector.parsers.apache_access import ApacheAccessEvent, parse_line


FIXTURES = Path(__file__).parents[2] / "data" / "fixtures" / "apache"


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8").rstrip("\n")


def test_normalize_apache_access_event():
    raw = read_fixture("access_combined_missing_values.log")
    event = parse_line(raw)

    assert event is not None
    normalized = normalize_apache_access_event(event)

    assert normalized.timestamp == datetime(2026, 9, 2, 12, 40, 5, tzinfo=timezone.utc)
    assert normalized.timestamp.tzinfo is timezone.utc
    assert normalized.source == "apache_access"
    assert normalized.event_type == "http_access"
    assert normalized.hostname is None
    assert normalized.username is None
    assert normalized.source_ip == "198.51.100.20"
    assert normalized.source_port is None
    assert normalized.success is None
    assert normalized.raw == raw
    assert normalized.service == "http"


def test_normalize_rejects_invalid_timestamp():
    event = ApacheAccessEvent(
        timestamp="invalid timestamp",
        client_ip=None,
        username=None,
        method="GET",
        path="/",
        protocol="HTTP/1.1",
        status_code=200,
        response_size=1,
        referrer=None,
        user_agent=None,
        raw="raw",
    )

    with pytest.raises(ValueError, match="Invalid Apache access timestamp"):
        normalize_apache_access_event(event)
