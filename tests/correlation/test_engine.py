from datetime import datetime, timedelta, timezone

from threat_detector.alerts.models import Alert
from threat_detector.correlation.engine import CorrelationEngine
from threat_detector.normalization.event import NormalizedEvent


BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)
SOURCE_IP = "192.0.2.10"


def make_event(
    offset: int,
    *,
    source_ip: str | None = SOURCE_IP,
    event_type: str = "authentication_success",
    service: str | None = "ssh",
    username: str | None = "root",
    raw: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=BASE_TIME + timedelta(seconds=offset),
        source="test",
        event_type=event_type,
        hostname="host",
        username=username,
        source_ip=source_ip,
        source_port=22,
        success=True,
        raw=raw or f"event-{offset}",
        service=service,
    )


def make_alert(
    alert_id: str = "alert-1",
    *,
    rule_id: str = "ssh_brute_force",
    offset: int = 0,
    source_ip: str | None = SOURCE_IP,
    raw_events: list[str] | None = None,
) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        severity="high",
        title="SSH brute force",
        description="Repeated SSH failures",
        timestamp=BASE_TIME + timedelta(seconds=offset),
        source_ip=source_ip,
        username="admin",
        evidence=["five failures"],
        raw_events=raw_events or [f"failure-{alert_id}"],
    )


def correlate(alert: Alert, event: NormalizedEvent):
    engine = CorrelationEngine()
    engine.process(
        NormalizedEvent(
            timestamp=alert.timestamp,
            source="test",
            event_type="other",
            hostname=None,
            username=None,
            source_ip=alert.source_ip,
            source_port=None,
            success=None,
            raw="alert-event",
            service=None,
        ),
        [alert],
    )
    return engine.process(event, [])


def test_matching_success_correlates_and_preserves_structured_evidence():
    alert = make_alert(raw_events=["failure-a", "failure-b"])
    event = make_event(180, username="root")

    findings = correlate(alert, event)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type == "credential_attack_success"
    assert finding.severity == "critical"
    assert finding.timestamp == event.timestamp
    assert finding.source_ip == SOURCE_IP
    assert finding.username == "root"
    assert finding.contributing_alerts == (alert,)
    assert finding.contributing_events == (event,)
    assert finding.raw_events == ("failure-a", "failure-b", "event-180")
    assert "elevated compromise risk" in finding.description
    assert "compromised" not in finding.description


def test_correlation_requires_strictly_later_same_source_ssh_success():
    alert = make_alert(offset=10)
    assert correlate(alert, make_event(9)) == []
    assert correlate(alert, make_event(10)) == []
    assert correlate(alert, make_event(191)) == []
    assert correlate(alert, make_event(11, source_ip="192.0.2.11")) == []
    assert correlate(make_alert(source_ip=None), make_event(11)) == []
    assert correlate(alert, make_event(11, source_ip=None)) == []
    assert correlate(alert, make_event(11, service="http")) == []
    assert correlate(alert, make_event(11, event_type="authentication_failure")) == []
    assert correlate(make_alert(rule_id="password_spraying"), make_event(1)) == []


def test_username_mismatch_does_not_block_correlation():
    assert correlate(make_alert(), make_event(1, username="root"))


def test_most_recent_alert_wins_with_alert_id_tie_breaking():
    engine = CorrelationEngine()
    engine.process(make_event(0, event_type="other"), [make_alert("older", offset=-10)])
    engine.process(make_event(1, event_type="other"), [make_alert("newer", offset=-1)])

    findings = engine.process(make_event(2), [])

    assert findings[0].contributing_alerts == (make_alert("newer", offset=-1),)

    tie_engine = CorrelationEngine()
    tie_engine.process(
        make_event(0, event_type="other"),
        [make_alert("a", offset=0), make_alert("b", offset=0)],
    )
    tie_findings = tie_engine.process(make_event(1), [])
    assert tie_findings[0].contributing_alerts == (make_alert("b", offset=0),)


def test_alerts_are_retained_per_source_and_expire_by_event_watermark():
    engine = CorrelationEngine()
    engine.process(make_event(0, event_type="other"), [make_alert()])
    assert engine.process(make_event(180), [])
    assert engine.process(make_event(181), []) == []

    isolated = CorrelationEngine()
    isolated.process(make_event(0, event_type="other"), [make_alert()])
    assert isolated.process(make_event(1, source_ip="192.0.2.11"), []) == []


def test_out_of_order_success_can_correlate_but_stale_success_cannot():
    engine = CorrelationEngine()
    engine.process(make_event(300, event_type="other"), [])
    engine.process(make_event(240, event_type="other"), [make_alert(offset=200)])
    assert engine.process(make_event(250), [])
    assert engine.process(make_event(100), []) == []


def test_late_brute_force_alert_does_not_retroactively_correlate_success():
    engine = CorrelationEngine()
    assert engine.process(make_event(10), []) == []
    assert engine.process(make_event(0, event_type="other"), [make_alert()]) == []


def test_separate_correlation_engines_do_not_share_state():
    first = CorrelationEngine()
    second = CorrelationEngine()
    first.process(make_event(0, event_type="other"), [make_alert()])

    assert second.process(make_event(1), []) == []


def test_alert_timestamps_do_not_advance_watermark():
    engine = CorrelationEngine()
    engine.process(make_event(0, event_type="other"), [make_alert(offset=1000)])
    assert engine.process(make_event(1), []) == []


def test_multiple_successes_have_separate_deterministic_findings():
    alert = make_alert()
    engine = CorrelationEngine()
    engine.process(make_event(0, event_type="other"), [alert])

    first = engine.process(make_event(1, raw="same-success"), [])[0]
    second = engine.process(make_event(2, raw="second-success"), [])[0]

    assert first.contributing_events == (make_event(1, raw="same-success"),)
    assert second.contributing_events == (make_event(2, raw="second-success"),)
    assert first.finding_id != second.finding_id
    assert first.finding_id == correlate(alert, make_event(1, raw="same-success"))[0].finding_id
