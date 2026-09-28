import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threat_detector.alerts.models import Alert
from threat_detector.correlation.models import Finding
from threat_detector.investigation.view import build_finding_view, build_timeline
from threat_detector.normalization.event import NormalizedEvent


BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_investigation_domain_imports_do_not_load_persistence():
    source_root = Path(__file__).resolve().parents[2] / "src"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(source_root), environment.get("PYTHONPATH", "")]
    )
    script = "\n".join(
        [
            "import sys",
            "from threat_detector.investigation.models import FindingView",
            "from threat_detector.investigation.view import build_finding_view",
            "assert FindingView is not None and callable(build_finding_view)",
            "assert not any(name == 'threat_detector.persistence' or "
            "name.startswith('threat_detector.persistence.') for name in sys.modules)",
        ]
    )

    subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        env=environment,
        text=True,
    )


def make_alert(
    alert_id: str = "alert-1",
    *,
    rule_id: str = "ssh_brute_force",
    offset: int = 0,
    source_ip: str | None = "192.0.2.10",
    username: str | None = "admin",
    description: str = "Repeated SSH failures",
    raw_events: list[str] | None = None,
) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        severity="high",
        title="Alert title",
        description=description,
        timestamp=BASE_TIME + timedelta(seconds=offset),
        source_ip=source_ip,
        username=username,
        evidence=["evidence line"],
        raw_events=raw_events if raw_events is not None else [f"raw-{alert_id}"],
    )


def make_event(
    offset: int = 0,
    *,
    event_type: str = "authentication_success",
    source_ip: str | None = "192.0.2.10",
    username: str | None = "root",
    service: str | None = "ssh",
    success: bool | None = True,
    raw: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=BASE_TIME + timedelta(seconds=offset),
        source="test",
        event_type=event_type,
        hostname=None,
        username=username,
        source_ip=source_ip,
        source_port=22,
        success=success,
        raw=raw if raw is not None else f"raw-event-{offset}",
        service=service,
    )


def make_finding(
    *,
    finding_id: str = "finding-1",
    finding_type: str = "credential_attack_success",
    severity: str = "critical",
    timestamp: datetime | None = None,
    source_ip: str | None = "192.0.2.10",
    username: str | None = "root",
    evidence: tuple[str, ...] = ("evidence-1", "evidence-2"),
    contributing_alerts: tuple[Alert, ...] = (),
    contributing_events: tuple[NormalizedEvent, ...] = (),
    raw_events: tuple[str, ...] = ("raw-1", "raw-2"),
) -> Finding:
    return Finding(
        finding_id=finding_id,
        finding_type=finding_type,
        severity=severity,
        title="Finding title",
        description="Finding description",
        timestamp=timestamp or BASE_TIME,
        source_ip=source_ip,
        username=username,
        evidence=evidence,
        contributing_alerts=contributing_alerts,
        contributing_events=contributing_events,
        raw_events=raw_events,
    )


def test_finding_view_preserves_summary_fields():
    finding = make_finding()

    view = build_finding_view(finding)

    assert view.finding_id == finding.finding_id
    assert view.finding_type == finding.finding_type
    assert view.severity == finding.severity
    assert view.title == finding.title
    assert view.description == finding.description
    assert view.timestamp == finding.timestamp


def test_evidence_is_copied_exactly_from_finding():
    finding = make_finding(evidence=("first", "second", "third"))

    view = build_finding_view(finding)

    assert view.evidence == finding.evidence
    assert view.evidence is finding.evidence


def test_alert_only_finding_produces_valid_timeline():
    alert = make_alert(offset=0)
    finding = make_finding(contributing_alerts=(alert,), contributing_events=())

    timeline = build_timeline(finding)

    assert len(timeline.entries) == 1
    entry = timeline.entries[0]
    assert entry.kind == "alert"
    assert entry.source_label == alert.rule_id
    assert entry.description == alert.description
    assert entry.source_ip == alert.source_ip
    assert entry.username == alert.username


def test_event_only_finding_produces_valid_timeline():
    event = make_event(offset=0)
    finding = make_finding(contributing_alerts=(), contributing_events=(event,))

    timeline = build_timeline(finding)

    assert len(timeline.entries) == 1
    entry = timeline.entries[0]
    assert entry.kind == "event"
    assert entry.source_label == event.event_type
    assert entry.source_ip == event.source_ip
    assert entry.username == event.username


def test_mixed_alert_and_event_timeline_merges_chronologically():
    alert = make_alert(offset=0)
    event = make_event(offset=180)
    finding = make_finding(contributing_alerts=(alert,), contributing_events=(event,))

    timeline = build_timeline(finding)

    assert [entry.kind for entry in timeline.entries] == ["alert", "event"]


def test_timeline_ordering_is_ascending():
    early_alert = make_alert("early", offset=0)
    late_alert = make_alert("late", offset=100)
    finding = make_finding(contributing_alerts=(late_alert, early_alert))

    timeline = build_timeline(finding)

    assert [entry.source_label for entry in timeline.entries] == [
        early_alert.rule_id,
        late_alert.rule_id,
    ]
    assert timeline.entries[0].timestamp < timeline.entries[1].timestamp


def test_alert_tie_ordering_is_deterministic():
    alert_b = make_alert("b", offset=0, rule_id="web_reconnaissance")
    alert_a = make_alert("a", offset=0, rule_id="password_spraying")
    finding = make_finding(contributing_alerts=(alert_b, alert_a))

    timeline = build_timeline(finding)

    assert [entry.source_label for entry in timeline.entries] == [
        "password_spraying",
        "web_reconnaissance",
    ]

    repeated = build_timeline(finding)
    assert repeated.entries == timeline.entries


def test_same_timestamp_alert_and_event_ordering_is_deterministic():
    alert = make_alert(offset=0)
    event = make_event(offset=0)
    finding = make_finding(contributing_alerts=(alert,), contributing_events=(event,))

    timeline = build_timeline(finding)

    assert timeline.entries[0].kind == "alert"
    assert timeline.entries[1].kind == "event"


def test_empty_contributing_events_is_valid():
    alert = make_alert(offset=0)
    finding = make_finding(contributing_alerts=(alert,), contributing_events=())

    timeline = build_timeline(finding)

    assert len(timeline.entries) == 1
    assert timeline.entries[0].kind == "alert"


def test_source_ip_becomes_entity():
    finding = make_finding(source_ip="192.0.2.50", username=None, contributing_alerts=())

    view = build_finding_view(finding)

    assert ("source_ip", "192.0.2.50") in {(e.kind, e.value) for e in view.entities}


def test_username_becomes_entity():
    finding = make_finding(source_ip=None, username="root", contributing_alerts=())

    view = build_finding_view(finding)

    assert ("username", "root") in {(e.kind, e.value) for e in view.entities}


def test_duplicate_entities_are_removed_deterministically():
    alert = make_alert(offset=0, source_ip="192.0.2.10", username="root")
    finding = make_finding(
        source_ip="192.0.2.10",
        username="root",
        contributing_alerts=(alert,),
    )

    view = build_finding_view(finding)

    ip_entities = [e for e in view.entities if e.kind == "source_ip"]
    username_entities = [e for e in view.entities if e.kind == "username"]
    assert len(ip_entities) == 1
    assert len(username_entities) == 1


def test_multiple_structured_usernames_produce_multiple_entity_refs():
    brute_force_alert = make_alert(offset=0, username="admin")
    success_event = make_event(offset=180, username="root")
    finding = make_finding(
        username="root",
        contributing_alerts=(brute_force_alert,),
        contributing_events=(success_event,),
    )

    view = build_finding_view(finding)

    usernames = {e.value for e in view.entities if e.kind == "username"}
    assert usernames == {"admin", "root"}


def test_password_spraying_usernames_not_extracted_from_evidence():
    spray_alert = make_alert(
        "spray-1",
        rule_id="password_spraying",
        offset=0,
        username=None,
        description=(
            "Source 192.0.2.10 attempted authentication for 5 distinct "
            "usernames within 60 seconds: alice, bob, carol, dave, eve."
        ),
    )
    finding = make_finding(
        finding_type="reconnaissance_credential_attack",
        source_ip="192.0.2.10",
        username=None,
        contributing_alerts=(spray_alert,),
    )

    view = build_finding_view(finding)

    usernames = {e.value for e in view.entities if e.kind == "username"}
    assert usernames == set()
    for name in ("alice", "bob", "carol", "dave", "eve"):
        assert name not in usernames


def test_normalized_event_raw_never_used_in_timeline():
    event = make_event(offset=0, raw="SECRET_RAW_EVENT_MARKER")
    finding = make_finding(contributing_alerts=(), contributing_events=(event,))

    timeline = build_timeline(finding)

    for entry in timeline.entries:
        assert "SECRET_RAW_EVENT_MARKER" not in entry.description


def test_alert_raw_events_never_used_in_timeline():
    alert = make_alert(offset=0, raw_events=["SECRET_RAW_ALERT_MARKER"])
    finding = make_finding(contributing_alerts=(alert,), contributing_events=())

    timeline = build_timeline(finding)

    for entry in timeline.entries:
        assert "SECRET_RAW_ALERT_MARKER" not in entry.description


def test_builders_do_not_mutate_finding_or_contributing_objects():
    alert = make_alert(offset=0)
    event = make_event(offset=10)
    finding = make_finding(contributing_alerts=(alert,), contributing_events=(event,))
    finding_before = make_finding(contributing_alerts=(alert,), contributing_events=(event,))

    build_finding_view(finding)

    assert finding == finding_before
    assert finding.contributing_alerts == (alert,)
    assert finding.contributing_events == (event,)


def test_building_same_finding_twice_is_deterministic():
    alert = make_alert(offset=0)
    event = make_event(offset=10)
    finding = make_finding(contributing_alerts=(alert,), contributing_events=(event,))

    first = build_finding_view(finding)
    second = build_finding_view(finding)

    assert first == second
