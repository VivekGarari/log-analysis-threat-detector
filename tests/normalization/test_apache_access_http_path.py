from pathlib import Path

from threat_detector.normalization.apache_access import normalize_apache_access_event
from threat_detector.parsers.apache_access import parse_line


FIXTURES = Path(__file__).parents[2] / "data" / "fixtures" / "apache"


def test_normalize_apache_access_event_populates_http_path():
    raw = (FIXTURES / "access_combined_200.log").read_text(encoding="utf-8").rstrip("\n")
    event = parse_line(raw)

    assert event is not None
    normalized = normalize_apache_access_event(event)

    assert normalized.http_path == "/login"


def test_normalize_apache_access_event_missing_values_has_none_http_path():
    raw = (FIXTURES / "access_combined_missing_values.log").read_text(encoding="utf-8").rstrip("\n")
    event = parse_line(raw)

    assert event is not None
    normalized = normalize_apache_access_event(event)

    assert normalized.http_path == "/health"


def test_normalize_linux_auth_does_not_populate_http_path():
    from datetime import datetime, timezone

    from threat_detector.normalization.linux_auth import normalize_linux_event
    from threat_detector.parsers.linux_auth import parse_line

    raw = "Jan  1 00:00:00 web-01 sshd[1001]: Failed password for alice from 203.0.113.50 port 2222"
    event = parse_line(raw)

    assert event is not None
    normalized = normalize_linux_event(event, datetime(2026, 9, 2, 12, tzinfo=timezone.utc))

    assert normalized.http_path is None


def test_normalize_windows_security_does_not_populate_http_path():
    from threat_detector.normalization.windows_security import normalize_windows_security_event
    from threat_detector.parsers.windows_security import parse_event

    raw = (Path(__file__).parents[2] / "data" / "fixtures" / "windows" / "security_4625.xml").read_text(encoding="utf-8")
    event = parse_event(raw)

    assert event is not None
    normalized = normalize_windows_security_event(event)

    assert normalized.http_path is None


def test_apache_access_passes_through_web_reconnaissance_detection():
    from threat_detector.detection.engine import DetectionEngine
    from threat_detector.detection.rules.web_reconnaissance import WebReconnaissanceRule

    raw = (FIXTURES / "access_combined_200.log").read_text(encoding="utf-8").rstrip("\n")
    parsed = parse_line(raw)

    assert parsed is not None
    normalized = normalize_apache_access_event(parsed)

    alerts = DetectionEngine([WebReconnaissanceRule()]).process(normalized)

    assert alerts == []


def test_apache_access_with_suspicious_paths_trigger_web_reconnaissance():
    from threat_detector.detection.engine import DetectionEngine
    from threat_detector.detection.rules.web_reconnaissance import WebReconnaissanceRule
    from datetime import datetime, timezone

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    rule = WebReconnaissanceRule()
    engine = DetectionEngine([rule])
    alerts = []
    for i, path in enumerate(
        ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/server-status"]
    ):
        raw = f'203.0.113.10 - alice [02/Sep/2026:12:40:01 +0000] "GET {path} HTTP/1.1" 200 512 "https://example.com" "Mozilla/5.0"'
        event = parse_line(raw)
        assert event is not None
        normalized = normalize_apache_access_event(event)
        normalized.timestamp = normalized.timestamp.replace(hour=12, minute=40, second=i * 10)
        alerts.append(engine.process(normalized))

    assert alerts[:4] == [[], [], [], []]
    assert len(alerts[4]) == 1
    assert alerts[4][0].rule_id == "web_reconnaissance"