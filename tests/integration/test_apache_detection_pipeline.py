from pathlib import Path

from threat_detector.detection.engine import DetectionEngine
from threat_detector.detection.rules.ssh_brute_force import SSHBruteForceRule
from threat_detector.detection.rules.web_reconnaissance import WebReconnaissanceRule
from threat_detector.normalization.apache_access import normalize_apache_access_event
from threat_detector.parsers.apache_access import parse_line


FIXTURES = Path(__file__).parents[2] / "data" / "fixtures" / "apache"


def test_apache_access_passes_through_detection_engine():
    raw = (FIXTURES / "access_combined_200.log").read_text(encoding="utf-8").rstrip("\n")
    parsed = parse_line(raw)

    assert parsed is not None
    normalized = normalize_apache_access_event(parsed)

    alerts = DetectionEngine([SSHBruteForceRule()]).process(normalized)

    assert alerts == []


def test_apache_access_with_suspicious_paths_triggers_web_reconnaissance():
    from datetime import datetime, timezone

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    rule = WebReconnaissanceRule()
    engine = DetectionEngine([rule])
    alerts = []
    for i, path in enumerate(
        ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/server-status"]
    ):
        raw = (
            f'203.0.113.10 - alice [02/Sep/2026:12:40:01 +0000] '
            f'"GET {path} HTTP/1.1" 200 512 "https://example.com" "Mozilla/5.0"'
        )
        event = parse_line(raw)
        normalized = normalize_apache_access_event(event)
        normalized.timestamp = normalized.timestamp.replace(
            hour=12, minute=40, second=i * 10
        )
        alerts.append(engine.process(normalized))

    assert alerts[:4] == [[], [], [], []]
    assert len(alerts[4]) == 1
    assert alerts[4][0].rule_id == "web_reconnaissance"