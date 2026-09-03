from pathlib import Path

from threat_detector.detection.engine import DetectionEngine
from threat_detector.detection.rules.ssh_brute_force import SSHBruteForceRule
from threat_detector.normalization.windows_security import (
    normalize_windows_security_event,
)
from threat_detector.parsers.windows_security import parse_event


FIXTURES = Path(__file__).parents[2] / "data" / "fixtures" / "windows"


def test_windows_authentication_failure_passes_through_detection_engine():
    raw = (FIXTURES / "security_4625.xml").read_text(encoding="utf-8")
    parsed = parse_event(raw)

    assert parsed is not None
    normalized = normalize_windows_security_event(parsed)

    alerts = DetectionEngine([SSHBruteForceRule()]).process(normalized)

    assert alerts == []
