import json
import sqlite3
from collections.abc import Iterable
from datetime import datetime

from threat_detector.alerts.models import Alert
from threat_detector.correlation.models import Finding
from threat_detector.normalization.event import NormalizedEvent


def _timestamp_to_text(timestamp: datetime) -> str:
    return timestamp.isoformat()


def _timestamp_from_text(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _success_to_int(success: bool | None) -> int | None:
    return None if success is None else int(success)


def _success_from_int(value: int | None) -> bool | None:
    return None if value is None else bool(value)


def _encode_strings(values: Iterable[str]) -> str:
    return json.dumps(list(values))


def _decode_strings(value: str) -> tuple[str, ...]:
    return tuple(json.loads(value))


def _insert_normalized_event(connection: sqlite3.Connection, event: NormalizedEvent) -> int:
    cursor = connection.execute(
        """
        INSERT INTO normalized_events (
            timestamp, source, event_type, hostname, username, source_ip,
            source_port, success, raw, service, http_path
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _timestamp_to_text(event.timestamp),
            event.source,
            event.event_type,
            event.hostname,
            event.username,
            event.source_ip,
            event.source_port,
            _success_to_int(event.success),
            event.raw,
            event.service,
            event.http_path,
        ),
    )
    assert cursor.lastrowid is not None
    return cursor.lastrowid


def _event_from_row(row: sqlite3.Row) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=_timestamp_from_text(row["timestamp"]),
        source=row["source"],
        event_type=row["event_type"],
        hostname=row["hostname"],
        username=row["username"],
        source_ip=row["source_ip"],
        source_port=row["source_port"],
        success=_success_from_int(row["success"]),
        raw=row["raw"],
        service=row["service"],
        http_path=row["http_path"],
    )


def save_normalized_event(connection: sqlite3.Connection, event: NormalizedEvent) -> int:
    with connection:
        return _insert_normalized_event(connection, event)


def load_normalized_event(connection: sqlite3.Connection, event_pk: int) -> NormalizedEvent:
    row = connection.execute(
        "SELECT * FROM normalized_events WHERE event_pk = ?", (event_pk,)
    ).fetchone()
    if row is None:
        raise LookupError(f"No normalized_events row for event_pk={event_pk}")
    return _event_from_row(row)


def _insert_alert(connection: sqlite3.Connection, alert: Alert) -> int:
    cursor = connection.execute(
        """
        INSERT INTO alerts (
            alert_id, rule_id, severity, title, description, timestamp,
            source_ip, username, evidence, raw_events
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert.alert_id,
            alert.rule_id,
            alert.severity,
            alert.title,
            alert.description,
            _timestamp_to_text(alert.timestamp),
            alert.source_ip,
            alert.username,
            _encode_strings(alert.evidence),
            _encode_strings(alert.raw_events),
        ),
    )
    assert cursor.lastrowid is not None
    return cursor.lastrowid


def _alert_from_row(row: sqlite3.Row) -> Alert:
    return Alert(
        alert_id=row["alert_id"],
        rule_id=row["rule_id"],
        severity=row["severity"],
        title=row["title"],
        description=row["description"],
        timestamp=_timestamp_from_text(row["timestamp"]),
        source_ip=row["source_ip"],
        username=row["username"],
        evidence=list(_decode_strings(row["evidence"])),
        raw_events=list(_decode_strings(row["raw_events"])),
    )


def save_alert(connection: sqlite3.Connection, alert: Alert) -> int:
    with connection:
        return _insert_alert(connection, alert)


def load_alert(connection: sqlite3.Connection, alert_pk: int) -> Alert:
    row = connection.execute(
        "SELECT * FROM alerts WHERE alert_pk = ?", (alert_pk,)
    ).fetchone()
    if row is None:
        raise LookupError(f"No alerts row for alert_pk={alert_pk}")
    return _alert_from_row(row)


def save_finding(connection: sqlite3.Connection, finding: Finding) -> int:
    """Persist a Finding and its contributing Alerts/NormalizedEvents atomically."""
    with connection:
        cursor = connection.execute(
            """
            INSERT INTO findings (
                finding_id, finding_type, severity, title, description,
                timestamp, source_ip, username, evidence, raw_events
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.finding_id,
                finding.finding_type,
                finding.severity,
                finding.title,
                finding.description,
                _timestamp_to_text(finding.timestamp),
                finding.source_ip,
                finding.username,
                _encode_strings(finding.evidence),
                _encode_strings(finding.raw_events),
            ),
        )
        finding_pk = cursor.lastrowid
        assert finding_pk is not None

        for position, alert in enumerate(finding.contributing_alerts):
            alert_pk = _insert_alert(connection, alert)
            connection.execute(
                "INSERT INTO finding_alerts (finding_pk, alert_pk, position) "
                "VALUES (?, ?, ?)",
                (finding_pk, alert_pk, position),
            )

        for position, event in enumerate(finding.contributing_events):
            event_pk = _insert_normalized_event(connection, event)
            connection.execute(
                "INSERT INTO finding_events (finding_pk, event_pk, position) "
                "VALUES (?, ?, ?)",
                (finding_pk, event_pk, position),
            )

    return finding_pk


def load_finding(connection: sqlite3.Connection, finding_pk: int) -> Finding:
    row = connection.execute(
        "SELECT * FROM findings WHERE finding_pk = ?", (finding_pk,)
    ).fetchone()
    if row is None:
        raise LookupError(f"No findings row for finding_pk={finding_pk}")

    alert_rows = connection.execute(
        "SELECT alert_pk FROM finding_alerts WHERE finding_pk = ? ORDER BY position",
        (finding_pk,),
    ).fetchall()
    contributing_alerts = tuple(
        load_alert(connection, alert_row["alert_pk"]) for alert_row in alert_rows
    )

    event_rows = connection.execute(
        "SELECT event_pk FROM finding_events WHERE finding_pk = ? ORDER BY position",
        (finding_pk,),
    ).fetchall()
    contributing_events = tuple(
        load_normalized_event(connection, event_row["event_pk"])
        for event_row in event_rows
    )

    return Finding(
        finding_id=row["finding_id"],
        finding_type=row["finding_type"],
        severity=row["severity"],
        title=row["title"],
        description=row["description"],
        timestamp=_timestamp_from_text(row["timestamp"]),
        source_ip=row["source_ip"],
        username=row["username"],
        evidence=_decode_strings(row["evidence"]),
        contributing_alerts=contributing_alerts,
        contributing_events=contributing_events,
        raw_events=_decode_strings(row["raw_events"]),
    )
