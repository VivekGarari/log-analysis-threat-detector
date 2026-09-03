from datetime import datetime, timezone

from threat_detector.detection.engine import DetectionEngine
from threat_detector.detection.rules.invalid_user import InvalidUserRule
from threat_detector.detection.rules.ssh_brute_force import SSHBruteForceRule
from threat_detector.normalization.event import NormalizedEvent


def make_event(
    event_type: str = "invalid_user",
    *,
    source: str = "linux_auth",
    service: str | None = "ssh",
    source_ip: str | None = "192.0.2.10",
    username: str | None = "unknown60",
    timestamp: datetime | None = None,
    raw: str = "raw invalid user event",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp or datetime(2026, 1, 1, tzinfo=timezone.utc),
        source=source,
        event_type=event_type,
        hostname="server",
        username=username,
        source_ip=source_ip,
        source_port=22,
        success=False,
        raw=raw,
        service=service,
    )


def test_invalid_user_produces_alert_with_event_context():
    event = make_event()

    alert = InvalidUserRule().process(event)

    assert alert is not None
    assert alert.rule_id == "invalid_user"
    assert alert.severity == "medium"
    assert alert.timestamp == event.timestamp
    assert alert.source_ip == event.source_ip
    assert alert.username == event.username
    assert alert.raw_events == [event.raw]
    assert alert.evidence == [
        "Invalid user unknown60 from 192.0.2.10 at 2026-01-01 00:00:00+00:00"
    ]


def test_non_invalid_user_events_do_not_trigger():
    rule = InvalidUserRule()

    assert rule.process(make_event("authentication_failure")) is None
    assert rule.process(make_event("authentication_success")) is None
    assert rule.process(make_event("http_access", source="apache_access", service="http")) is None


def test_rule_does_not_retain_state_between_events():
    rule = InvalidUserRule()

    first_alert = rule.process(make_event(raw="first raw event"))
    second_alert = rule.process(make_event(raw="second raw event"))

    assert first_alert is not None
    assert second_alert is not None
    assert first_alert.raw_events == ["first raw event"]
    assert second_alert.raw_events == ["second raw event"]
    assert first_alert is not second_alert


def test_engine_runs_ssh_and_invalid_user_rules_without_interference():
    engine = DetectionEngine([SSHBruteForceRule(), InvalidUserRule()])
    events = [
        make_event("invalid_user", service="http", raw="invalid user event")
    ]
    events.extend(
        make_event(
            "authentication_failure",
            source="linux_auth",
            service="ssh",
            username="alice",
            raw=f"ssh failure {index}",
        )
        for index in range(5)
    )

    results = [engine.process(event) for event in events]

    assert len(results[0]) == 1
    assert results[0][0].rule_id == "invalid_user"
    assert len(results[-1]) == 1
    assert results[-1][0].rule_id == "ssh_brute_force"