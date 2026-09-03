from datetime import datetime, timezone

from threat_detector.alerts.models import Alert
from threat_detector.reporting.text import report


def make_alert(
    alert_id: str = "alert-1",
    source_ip: str | None = "192.0.2.10",
    username: str | None = "alice",
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
        raw_events=["raw event one", "raw event two"],
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
