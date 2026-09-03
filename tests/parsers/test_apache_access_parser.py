from pathlib import Path

from threat_detector.parsers.apache_access import parse_line


FIXTURES = Path(__file__).parents[2] / "data" / "fixtures" / "apache"


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8").rstrip("\n")


def test_parse_representative_combined_access_record():
    raw = read_fixture("access_combined_200.log")

    event = parse_line(raw)

    assert event is not None
    assert event.timestamp == "02/Sep/2026:12:40:01 +0000"
    assert event.client_ip == "203.0.113.10"
    assert event.username == "alice"
    assert event.method == "GET"
    assert event.path == "/login"
    assert event.protocol == "HTTP/1.1"
    assert event.status_code == 200
    assert event.response_size == 512
    assert event.referrer == "https://portal.example.test/"
    assert event.user_agent.startswith("Mozilla/5.0")
    assert event.raw == raw


def test_parse_combined_record_converts_placeholders_to_none():
    event = parse_line(read_fixture("access_combined_missing_values.log"))

    assert event is not None
    assert event.client_ip == "198.51.100.20"
    assert event.username is None
    assert event.response_size is None
    assert event.referrer is None
    assert event.user_agent is None


def test_parse_rejects_malformed_or_incomplete_record():
    assert parse_line('203.0.113.10 - alice [02/Sep/2026:12:40:01 +0000] "GET /login HTTP/1.1" 200') is None
    assert parse_line("not an apache access record") is None


def test_parse_rejects_invalid_numeric_fields():
    raw = read_fixture("access_combined_200.log")

    assert parse_line(raw.replace('" 200 512 "', '" abc 512 "')) is None
    assert parse_line(raw.replace('" 200 512 "', '" 200 bytes "')) is None


def test_parse_rejects_non_combined_format():
    assert parse_line("203.0.113.10 - - [02/Sep/2026:12:40:01 +0000] \\\"GET /login HTTP/1.1\\\" 200 512") is None
