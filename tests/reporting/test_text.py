from datetime import datetime, timezone

from threat_detector.alerts.models import Alert
from threat_detector.reporting.text import report


def make_alert(
    alert_id: str = "alert-1",
    source_ip: str | None = "192.0.2.10",
    username: str | None = "alice",
    raw_events: list[str] | None = None,
) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id="ssh_brute_force",
        severity="high",
        title="SSH brute force",
        description="Repeated authentication failures",
        timestamp=datetime(2026, 9, 3, 12, 30, tzinfo=timezone.utc),
        source_ip=source_ip,
        username=username,
        evidence=["five failed logins", "same source address"],
        raw_events=(
            ["raw event one", "raw event two"]
            if raw_events is None
            else raw_events
        ),
    )


def test_one_alert_contains_all_fields_and_collections():
    output = report([make_alert()])

    for value in (
        "alert-1",
        "ssh_brute_force",
        "high",
        "SSH brute force",
        "Repeated authentication failures",
        "2026-09-03T12:30:00+00:00",
        "192.0.2.10",
        "alice",
        "five failed logins",
        "same source address",
        "raw event one",
        "raw event two",
    ):
        assert value in output


def test_none_fields_use_consistent_placeholder():
    output = report([make_alert(source_ip=None, username=None)])

    assert "source_ip: N/A" in output
    assert "username: N/A" in output
    assert "None" not in output


def test_multiple_alerts_preserve_input_order():
    output = report([make_alert("first"), make_alert("second")])

    assert output.index("first") < output.index("second")


def test_empty_input_returns_empty_string():
    assert report([]) == ""


def test_raw_events_escape_terminal_control_characters():
    raw_event = (
        "before\x1b[31mred\x1b[0m"
        "\x1b]0;attacker title\x07"
        "bell\x07 carriage\rreturn nul\x00 del\x7f c1\x9b"
        " bidi\u202eend"
    )

    output = report([make_alert(raw_events=[raw_event])])

    assert "before\\x1b[31mred\\x1b[0m" in output
    assert "\\x1b]0;attacker title\\x07" in output
    assert "bell\\x07 carriage\\x0dreturn nul\\x00" in output
    assert "del\\x7f c1\\x9b bidi\\u202eend" in output
    assert all(character not in output for character in "\x1b\x07\r\x00\x7f\x9b\u202e")


def test_raw_events_preserve_ordinary_printable_text():
    output = report([make_alert(raw_events=["GET /login?user=alice HTTP/1.1"])])

    assert "  - GET /login?user=alice HTTP/1.1" in output
