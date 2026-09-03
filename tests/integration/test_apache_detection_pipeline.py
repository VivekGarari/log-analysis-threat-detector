from pathlib import Path

from threat_detector.detection.engine import DetectionEngine
from threat_detector.detection.rules.ssh_brute_force import SSHBruteForceRule
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
