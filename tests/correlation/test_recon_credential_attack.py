from datetime import datetime, timedelta, timezone

from threat_detector.alerts.models import Alert
from threat_detector.correlation.engine import CorrelationEngine
from threat_detector.normalization.event import NormalizedEvent


BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)
SOURCE_IP = "192.0.2.20"


def make_recon_alert(
    alert_id: str = "recon-1",
    *,
    offset: int = 0,
    source_ip: str | None = SOURCE_IP,
) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id="web_reconnaissance",
        severity="medium",
        title="Web reconnaissance detected",
        description=(
            "Source requested 5 distinct suspicious paths within 60 seconds."
        ),
        timestamp=BASE_TIME + timedelta(seconds=offset),
        source_ip=source_ip,
        username=None,
        evidence=["suspicious path evidence"],
        raw_events=[f"recon-raw-{alert_id}"],
    )


def make_spray_alert(
    alert_id: str = "spray-1",
    *,
    offset: int = 0,
    source_ip: str | None = SOURCE_IP,
) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id="password_spraying",
        severity="high",
        title="Password spraying activity detected",
        description=(
            "Source attempted authentication for 5 distinct usernames within "
            "60 seconds."
        ),
        timestamp=BASE_TIME + timedelta(seconds=offset),
        source_ip=source_ip,
        username=None,
        evidence=["username evidence"],
        raw_events=[f"spray-raw-{alert_id}"],
    )


def make_carrier_event(
    offset: int, *, microseconds: int = 0, source_ip: str | None = SOURCE_IP
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=BASE_TIME + timedelta(seconds=offset, microseconds=microseconds),
        source="test",
        event_type="other",
        hostname=None,
        username=None,
        source_ip=source_ip,
        source_port=None,
        success=None,
        raw=f"event-{offset}",
        service=None,
    )


def test_recon_followed_by_spraying_correlates():
    engine = CorrelationEngine()
    recon = make_recon_alert(offset=0)
    spray = make_spray_alert(offset=90)

    engine.process(make_carrier_event(0), [recon])
    findings = engine.process(make_carrier_event(90), [spray])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type == "reconnaissance_credential_attack"
    assert finding.severity == "high"
    assert finding.timestamp == spray.timestamp
    assert finding.source_ip == SOURCE_IP
    assert finding.username is None
    assert finding.contributing_alerts == (recon, spray)
    assert finding.contributing_events == ()
    assert finding.raw_events == tuple(recon.raw_events) + tuple(spray.raw_events)
    assert finding.finding_id == (
        f"reconnaissance_credential_attack:{SOURCE_IP}:"
        f"{recon.alert_id}:{spray.alert_id}"
    )
    assert "does not" in finding.description
    assert "compromised" not in finding.description


def test_different_source_ip_does_not_correlate():
    engine = CorrelationEngine()
    engine.process(make_carrier_event(0), [make_recon_alert(offset=0)])

    findings = engine.process(
        make_carrier_event(10, source_ip="192.0.2.21"),
        [make_spray_alert(offset=10, source_ip="192.0.2.21")],
    )

    assert findings == []


def test_equal_timestamps_do_not_correlate():
    engine = CorrelationEngine()
    engine.process(make_carrier_event(0), [make_recon_alert(offset=0)])

    findings = engine.process(make_carrier_event(0), [make_spray_alert(offset=0)])

    assert findings == []


def test_exactly_180_seconds_correlates():
    engine = CorrelationEngine()
    engine.process(make_carrier_event(0), [make_recon_alert(offset=0)])

    findings = engine.process(make_carrier_event(180), [make_spray_alert(offset=180)])

    assert len(findings) == 1


def test_181_seconds_does_not_correlate():
    engine = CorrelationEngine()
    engine.process(make_carrier_event(0), [make_recon_alert(offset=0)])

    findings = engine.process(make_carrier_event(181), [make_spray_alert(offset=181)])

    assert findings == []


def test_recon_expiry_keeps_boundary_and_expires_after_microsecond():
    engine = CorrelationEngine()
    engine.process(make_carrier_event(0), [make_recon_alert()])

    engine.process(make_carrier_event(180), [])
    assert len(engine._recon_alerts_by_source_ip[SOURCE_IP]) == 1

    engine.process(make_carrier_event(180, microseconds=1), [])
    assert engine._recon_alerts_by_source_ip == {}
    assert engine._recon_expiry_heap == []


def test_replayed_recon_alert_insertions_expire_independently():
    engine = CorrelationEngine()
    replay = make_recon_alert("replayed")
    engine.process(make_carrier_event(0), [replay, replay])

    assert len(engine._recon_alerts_by_source_ip[SOURCE_IP]) == 2
    assert len(engine._recon_expiry_heap) == 2

    engine.process(make_carrier_event(180, microseconds=1), [])

    assert engine._recon_alerts_by_source_ip == {}
    assert engine._recon_expiry_heap == []


def test_recon_expiry_removes_only_sources_past_the_boundary():
    engine = CorrelationEngine()
    first_source = "192.0.2.31"
    second_source = "192.0.2.32"
    active_source = "192.0.2.33"
    engine.process(
        make_carrier_event(0),
        [
            make_recon_alert("first", source_ip=first_source),
            make_recon_alert("second", source_ip=second_source),
        ],
    )
    engine.process(
        make_carrier_event(1),
        [make_recon_alert("active", offset=1, source_ip=active_source)],
    )

    engine.process(make_carrier_event(180, microseconds=1), [])

    assert set(engine._recon_alerts_by_source_ip) == {active_source}
    assert len(engine._recon_alerts_by_source_ip[active_source]) == 1
    assert len(engine._recon_expiry_heap) == 1


def test_expired_recon_alert_is_replaced_by_fresh_correlation():
    engine = CorrelationEngine()
    engine.process(make_carrier_event(0), [make_recon_alert("old")])
    engine.process(make_carrier_event(180, microseconds=1), [])
    assert engine.process(
        make_carrier_event(181), [make_spray_alert(offset=181)]
    ) == []

    fresh = make_recon_alert("fresh", offset=181)
    engine.process(make_carrier_event(181), [fresh])
    findings = engine.process(
        make_carrier_event(182), [make_spray_alert(offset=182)]
    )

    assert len(findings) == 1
    assert findings[0].contributing_alerts == (fresh, make_spray_alert(offset=182))


def test_spraying_alert_without_recon_context_does_not_correlate():
    engine = CorrelationEngine()

    findings = engine.process(make_carrier_event(0), [make_spray_alert(offset=0)])

    assert findings == []


def test_late_recon_alert_does_not_retroactively_correlate_past_spray():
    engine = CorrelationEngine()

    assert engine.process(make_carrier_event(50), [make_spray_alert(offset=50)]) == []
    # a recon alert with an earlier timestamp arrives late (out-of-order ingestion)
    assert engine.process(make_carrier_event(40), [make_recon_alert(offset=40)]) == []


def test_stale_recon_alert_is_expired_before_spray_arrives():
    engine = CorrelationEngine()
    engine.process(make_carrier_event(0), [make_recon_alert(offset=0)])
    engine.process(make_carrier_event(300), [])

    findings = engine.process(make_carrier_event(300), [make_spray_alert(offset=300)])

    assert findings == []


def test_out_of_order_recon_processing_within_window_still_correlates():
    engine = CorrelationEngine()
    engine.process(make_carrier_event(100), [])
    engine.process(make_carrier_event(50), [make_recon_alert(offset=50)])

    findings = engine.process(make_carrier_event(120), [make_spray_alert(offset=120)])

    assert len(findings) == 1


def test_multiple_recon_alerts_selects_most_recent():
    engine = CorrelationEngine()
    engine.process(make_carrier_event(0), [make_recon_alert("recon-old", offset=0)])
    engine.process(make_carrier_event(10), [make_recon_alert("recon-new", offset=10)])

    findings = engine.process(make_carrier_event(20), [make_spray_alert(offset=20)])

    assert findings[0].contributing_alerts[0].alert_id == "recon-new"


def test_equal_recon_timestamps_tie_break_by_alert_id():
    engine = CorrelationEngine()
    engine.process(
        make_carrier_event(0),
        [make_recon_alert("recon-a", offset=0), make_recon_alert("recon-b", offset=0)],
    )

    findings = engine.process(make_carrier_event(10), [make_spray_alert(offset=10)])

    assert findings[0].contributing_alerts[0].alert_id == "recon-b"


def test_multiple_spraying_alerts_each_produce_finding():
    engine = CorrelationEngine()
    engine.process(make_carrier_event(0), [make_recon_alert(offset=0)])

    findings = engine.process(
        make_carrier_event(10),
        [make_spray_alert("spray-a", offset=10), make_spray_alert("spray-b", offset=10)],
    )

    assert len(findings) == 2
    assert {finding.finding_id for finding in findings} == {
        f"reconnaissance_credential_attack:{SOURCE_IP}:recon-1:spray-a",
        f"reconnaissance_credential_attack:{SOURCE_IP}:recon-1:spray-b",
    }


def test_missing_source_ip_does_not_correlate():
    engine = CorrelationEngine()
    engine.process(
        make_carrier_event(0, source_ip=None),
        [make_recon_alert(offset=0, source_ip=None)],
    )

    findings = engine.process(
        make_carrier_event(10, source_ip=None),
        [make_spray_alert(offset=10, source_ip=None)],
    )

    assert findings == []


def test_evidence_and_raw_event_ordering_is_deterministic():
    engine = CorrelationEngine()
    recon = make_recon_alert(offset=0)
    spray = make_spray_alert(offset=10)
    engine.process(make_carrier_event(0), [recon])

    finding = engine.process(make_carrier_event(10), [spray])[0]

    assert finding.evidence[0].startswith("Web reconnaissance alert")
    assert finding.evidence[1] == recon.description
    assert finding.evidence[2].startswith("Password spraying alert")
    assert finding.evidence[3] == spray.description
    assert finding.raw_events == tuple(recon.raw_events) + tuple(spray.raw_events)


def test_separate_engines_do_not_share_recon_state():
    first = CorrelationEngine()
    second = CorrelationEngine()
    first.process(make_carrier_event(0), [make_recon_alert(offset=0)])

    findings = second.process(make_carrier_event(10), [make_spray_alert(offset=10)])

    assert findings == []
