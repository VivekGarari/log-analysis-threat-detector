from threat_detector.normalization.linux_auth import normalize_linux_event
from threat_detector.parsers.linux_auth import parse_line


def test_normalize_linux_event():
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Failed password for alice from 192.0.2.10 port 2222"
    )

    event = parse_line(raw)

    assert event is not None

    normalized = normalize_linux_event(event)

    assert normalized.timestamp == "Jan  1 12:34:56"
    assert normalized.source == "linux_auth"
    assert normalized.event_type == "authentication_failure"
    assert normalized.hostname == "server"
    assert normalized.username == "alice"
    assert normalized.source_ip == "192.0.2.10"
    assert normalized.source_port == 2222
    assert normalized.success is False
    assert normalized.raw == raw
