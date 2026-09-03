from pathlib import Path

from threat_detector.parsers.windows_security import parse_event


FIXTURES = Path(__file__).parents[2] / "data" / "fixtures" / "windows"


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_parse_successful_windows_security_logon():
    raw = read_fixture("security_4624.xml")

    event = parse_event(raw)

    assert event is not None
    assert event.timestamp == "2026-09-02T12:34:56.123456Z"
    assert event.hostname == "WIN-AUTH-01.example.test"
    assert event.event_id == 4624
    assert event.username == "alice"
    assert event.source_ip == "203.0.113.50"
    assert event.source_port == 49832
    assert event.raw == raw


def test_parse_failed_windows_security_logon():
    event = parse_event(read_fixture("security_4625.xml"))

    assert event is not None
    assert event.event_id == 4625
    assert event.username == "alice"
    assert event.source_ip is None
    assert event.source_port is None


def test_parse_rejects_malformed_xml():
    assert parse_event("<Event><System>") is None


def test_parse_rejects_unsupported_event_id():
    raw = read_fixture("security_4625.xml").replace("<EventID>4625</EventID>", "<EventID>4634</EventID>")

    assert parse_event(raw) is None
