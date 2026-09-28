import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from threat_detector.alerts.models import Alert
from threat_detector.correlation.models import Finding
from threat_detector.normalization.event import NormalizedEvent


@dataclass(frozen=True)
class FindingSummary:
    finding_pk: int
    finding_id: str
    finding_type: str
    severity: str
    title: str
    timestamp: datetime
    source_ip: str | None
    username: str | None


_UTC_EPOCH = datetime(1970, 1, 1)


def _timestamp_utc_microseconds(value: str | datetime) -> int:
    timestamp = datetime.fromisoformat(value) if isinstance(value, str) else value
    offset = timestamp.utcoffset()
    if timestamp.tzinfo is not None and offset is None:
        raise ValueError("Timestamp timezone offset is invalid")
    if offset is None:
        offset = timedelta(0)

    delta = timestamp.replace(tzinfo=None) - _UTC_EPOCH
    local_microseconds = (
        (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds
    )
    offset_microseconds = (
        (offset.days * 86_400 + offset.seconds) * 1_000_000 + offset.microseconds
    )
    return local_microseconds - offset_microseconds


def _timestamp_to_text(timestamp: datetime) -> str:
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Persisted timestamps must be timezone-aware")
    return timestamp.astimezone(timezone.utc).isoformat()


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


def list_findings(
    connection: sqlite3.Connection,
    *,
    severity: str | None = None,
    finding_type: str | None = None,
    source_ip: str | None = None,
    from_timestamp: datetime | None = None,
    to_timestamp: datetime | None = None,
    cursor: tuple[datetime, int] | None = None,
    limit: int = 50,
) -> list[FindingSummary]:
    connection.create_function(
        "timestamp_utc_microseconds",
        1,
        _timestamp_utc_microseconds,
        deterministic=True,
    )
    conditions: list[str] = []
    parameters: list[object] = []

    if severity is not None:
        conditions.append("severity = ?")
        parameters.append(severity)
    if finding_type is not None:
        conditions.append("finding_type = ?")
        parameters.append(finding_type)
    if source_ip is not None:
        conditions.append("source_ip = ?")
        parameters.append(source_ip)
    if from_timestamp is not None:
        conditions.append("timestamp_utc_microseconds(timestamp) >= ?")
        parameters.append(_timestamp_utc_microseconds(from_timestamp))
    if to_timestamp is not None:
        conditions.append("timestamp_utc_microseconds(timestamp) < ?")
        parameters.append(_timestamp_utc_microseconds(to_timestamp))
    if cursor is not None:
        cursor_timestamp, cursor_finding_pk = cursor
        cursor_microseconds = _timestamp_utc_microseconds(cursor_timestamp)
        conditions.append(
            "(timestamp_utc_microseconds(timestamp) < ? "
            "OR (timestamp_utc_microseconds(timestamp) = ? AND finding_pk < ?))"
        )
        parameters.extend(
            (cursor_microseconds, cursor_microseconds, cursor_finding_pk)
        )

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    rows = connection.execute(
        f"""
        SELECT finding_pk, finding_id, finding_type, severity, title,
               timestamp, source_ip, username
        FROM findings
        {where_clause}
        ORDER BY timestamp_utc_microseconds(timestamp) DESC, finding_pk DESC
        LIMIT ?
        """,
        (*parameters, limit + 1),
    ).fetchall()

    return [
        FindingSummary(
            finding_pk=row["finding_pk"],
            finding_id=row["finding_id"],
            finding_type=row["finding_type"],
            severity=row["severity"],
            title=row["title"],
            timestamp=_timestamp_from_text(row["timestamp"]),
            source_ip=row["source_ip"],
            username=row["username"],
        )
        for row in rows
    ]
