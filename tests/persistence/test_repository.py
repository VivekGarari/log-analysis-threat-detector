import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from threat_detector.alerts.models import Alert
from threat_detector.correlation.models import Finding
from threat_detector.investigation.view import build_finding_view
from threat_detector.normalization.event import NormalizedEvent
from threat_detector.persistence.repository import (
    load_alert,
    load_finding,
    load_normalized_event,
    save_alert,
    save_finding,
    save_normalized_event,
)
from threat_detector.persistence.schema import connect, initialize_schema


BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture()
def conn():
    connection = connect(":memory:")
    initialize_schema(connection)
    try:
        yield connection
    finally:
        connection.close()


def make_event(
    offset: int = 0,
    *,
    event_type: str = "authentication_success",
    hostname: str | None = "host",
    username: str | None = "root",
    source_ip: str | None = "192.0.2.10",
    source_port: int | None = 22,
    success: bool | None = True,
    raw: str | None = None,
    service: str | None = "ssh",
    http_path: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=BASE_TIME + timedelta(seconds=offset),
        source="test",
        event_type=event_type,
        hostname=hostname,
        username=username,
        source_ip=source_ip,
        source_port=source_port,
        success=success,
        raw=raw if raw is not None else f"raw-event-{offset}",
        service=service,
        http_path=http_path,
    )


def make_alert(
    alert_id: str = "alert-1",
    *,
    rule_id: str = "ssh_brute_force",
    severity: str = "high",
    offset: int = 0,
    source_ip: str | None = "192.0.2.10",
    username: str | None = "admin",
    evidence: list[str] | None = None,
    raw_events: list[str] | None = None,
) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        severity=severity,
        title="Alert title",
        description="Alert description",
        timestamp=BASE_TIME + timedelta(seconds=offset),
        source_ip=source_ip,
        username=username,
        evidence=evidence if evidence is not None else ["evidence line"],
        raw_events=raw_events if raw_events is not None else [f"raw-{alert_id}"],
    )


def make_finding(
    *,
    finding_id: str = "finding-1",
    finding_type: str = "credential_attack_success",
    severity: str = "critical",
    offset: int = 0,
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
        timestamp=BASE_TIME + timedelta(seconds=offset),
        source_ip=source_ip,
        username=username,
        evidence=evidence,
        contributing_alerts=contributing_alerts,
        contributing_events=contributing_events,
        raw_events=raw_events,
    )


# 1. schema initialization
def test_schema_initialization_creates_expected_tables(conn):
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
    ).fetchall()
    table_names = {row["name"] for row in rows}
    assert {
        "normalized_events",
        "alerts",
        "findings",
        "finding_alerts",
        "finding_events",
    } <= table_names


# 2. repeated schema initialization
def test_repeated_schema_initialization_is_safe(conn):
    initialize_schema(conn)
    initialize_schema(conn)
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
    ).fetchall()
    assert len(rows) == len({row["name"] for row in rows})


# 3. NormalizedEvent round-trip
def test_normalized_event_round_trip(conn):
    event = make_event(offset=0)

    event_pk = save_normalized_event(conn, event)
    loaded = load_normalized_event(conn, event_pk)

    assert loaded == event


# 4. Alert round-trip
def test_alert_round_trip(conn):
    alert = make_alert(offset=0)

    alert_pk = save_alert(conn, alert)
    loaded = load_alert(conn, alert_pk)

    assert loaded == alert


# 5. Finding round-trip
def test_finding_round_trip(conn):
    alert = make_alert(offset=0)
    finding = make_finding(contributing_alerts=(alert,))

    finding_pk = save_finding(conn, finding)
    loaded = load_finding(conn, finding_pk)

    assert loaded == finding


# 6. Finding with two Alerts and zero events
def test_finding_with_two_alerts_and_zero_events(conn):
    first_alert = make_alert("alert-a", offset=0, rule_id="web_reconnaissance")
    second_alert = make_alert("alert-b", offset=10, rule_id="password_spraying")
    finding = make_finding(
        finding_type="reconnaissance_credential_attack",
        contributing_alerts=(first_alert, second_alert),
        contributing_events=(),
    )

    finding_pk = save_finding(conn, finding)
    loaded = load_finding(conn, finding_pk)

    assert loaded.contributing_alerts == (first_alert, second_alert)
    assert loaded.contributing_events == ()


# 7. Finding with one Alert and one event
def test_finding_with_one_alert_and_one_event(conn):
    alert = make_alert(offset=0)
    event = make_event(offset=180, event_type="authentication_success")
    finding = make_finding(contributing_alerts=(alert,), contributing_events=(event,))

    finding_pk = save_finding(conn, finding)
    loaded = load_finding(conn, finding_pk)

    assert loaded.contributing_alerts == (alert,)
    assert loaded.contributing_events == (event,)


# 8. exact Alert tuple ordering
def test_alert_tuple_ordering_is_preserved(conn):
    later_alert = make_alert("later", offset=100)
    earlier_alert = make_alert("earlier", offset=0)
    # Insert in reverse-chronological order to prove ordering follows
    # position, not timestamp or insertion order.
    finding = make_finding(contributing_alerts=(later_alert, earlier_alert))

    finding_pk = save_finding(conn, finding)
    loaded = load_finding(conn, finding_pk)

    assert loaded.contributing_alerts == (later_alert, earlier_alert)


# 9. exact event tuple ordering
def test_event_tuple_ordering_is_preserved(conn):
    later_event = make_event(offset=200)
    earlier_event = make_event(offset=5)
    finding = make_finding(contributing_events=(later_event, earlier_event))

    finding_pk = save_finding(conn, finding)
    loaded = load_finding(conn, finding_pk)

    assert loaded.contributing_events == (later_event, earlier_event)


# 10. evidence round-trip (values, order, empty arrays)
def test_evidence_round_trip_including_empty(conn):
    alert = make_alert(evidence=["first", "second", "third"])
    finding = make_finding(contributing_alerts=(alert,), evidence=())

    finding_pk = save_finding(conn, finding)
    loaded = load_finding(conn, finding_pk)

    assert loaded.evidence == ()
    assert loaded.contributing_alerts[0].evidence == ["first", "second", "third"]


# 11. raw_events round-trip
def test_raw_events_round_trip(conn):
    alert = make_alert(raw_events=["raw-a", "raw-b"])
    finding = make_finding(contributing_alerts=(alert,), raw_events=())

    finding_pk = save_finding(conn, finding)
    loaded = load_finding(conn, finding_pk)

    assert loaded.raw_events == ()
    assert loaded.contributing_alerts[0].raw_events == ["raw-a", "raw-b"]


# 12. all nullable NormalizedEvent fields
def test_all_nullable_normalized_event_fields_round_trip_as_none(conn):
    event = make_event(
        hostname=None,
        username=None,
        source_ip=None,
        source_port=None,
        success=None,
        service=None,
        http_path=None,
    )

    event_pk = save_normalized_event(conn, event)
    loaded = load_normalized_event(conn, event_pk)

    assert loaded.hostname is None
    assert loaded.username is None
    assert loaded.source_ip is None
    assert loaded.source_port is None
    assert loaded.success is None
    assert loaded.service is None
    assert loaded.http_path is None


# 13. timezone-aware UTC timestamp round-trip
def test_timestamp_round_trips_as_timezone_aware_utc(conn):
    event = make_event(offset=0)

    event_pk = save_normalized_event(conn, event)
    loaded = load_normalized_event(conn, event_pk)

    assert loaded.timestamp.tzinfo is not None
    assert loaded.timestamp.utcoffset() == timedelta(0)
    assert loaded.timestamp == event.timestamp


# 14. foreign-key enforcement
def test_foreign_key_enforcement_rejects_orphan_link_row(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO finding_alerts (finding_pk, alert_pk, position) "
            "VALUES (?, ?, ?)",
            (999, 999, 0),
        )


# 15. invalid relationship insertion fails
def test_invalid_finding_event_relationship_fails(conn):
    alert = make_alert(offset=0)
    finding = make_finding(contributing_alerts=(alert,))
    finding_pk = save_finding(conn, finding)

    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO finding_events (finding_pk, event_pk, position) "
            "VALUES (?, ?, ?)",
            (finding_pk, 999, 0),
        )


# 16. duplicate/replayed logical objects create separate DB rows
def test_replaying_the_same_alert_creates_separate_rows(conn):
    alert = make_alert(offset=0)

    first_pk = save_alert(conn, alert)
    second_pk = save_alert(conn, alert)

    assert first_pk != second_pk
    count = conn.execute(
        "SELECT COUNT(*) AS n FROM alerts WHERE alert_id = ?", (alert.alert_id,)
    ).fetchone()["n"]
    assert count == 2


# 17. FindingView reconstructed from persisted Finding equals the original
def test_finding_view_from_persisted_finding_matches_original(conn):
    alert = make_alert(offset=0)
    event = make_event(offset=180)
    finding = make_finding(contributing_alerts=(alert,), contributing_events=(event,))

    finding_pk = save_finding(conn, finding)
    loaded = load_finding(conn, finding_pk)

    assert build_finding_view(loaded) == build_finding_view(finding)


# 18. transaction rollback when Finding persistence fails partway
def test_finding_persistence_rolls_back_on_partial_failure(conn):
    good_alert = make_alert("good", offset=0)
    invalid_alert = make_alert("bad", offset=1)
    invalid_alert.severity = None  # violates the NOT NULL constraint on alerts.severity
    finding = make_finding(contributing_alerts=(good_alert, invalid_alert))

    with pytest.raises(sqlite3.IntegrityError):
        save_finding(conn, finding)

    findings_count = conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"]
    alerts_count = conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
    assert findings_count == 0
    assert alerts_count == 0
