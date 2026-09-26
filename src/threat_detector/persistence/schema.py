import sqlite3

_SCHEMA_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS normalized_events (
        event_pk INTEGER PRIMARY KEY,
        timestamp TEXT NOT NULL,
        source TEXT NOT NULL,
        event_type TEXT NOT NULL,
        hostname TEXT NULL,
        username TEXT NULL,
        source_ip TEXT NULL,
        source_port INTEGER NULL,
        success INTEGER NULL,
        raw TEXT NOT NULL,
        service TEXT NULL,
        http_path TEXT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS alerts (
        alert_pk INTEGER PRIMARY KEY,
        alert_id TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        source_ip TEXT NULL,
        username TEXT NULL,
        evidence TEXT NOT NULL,
        raw_events TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
        finding_pk INTEGER PRIMARY KEY,
        finding_id TEXT NOT NULL,
        finding_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        source_ip TEXT NULL,
        username TEXT NULL,
        evidence TEXT NOT NULL,
        raw_events TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS finding_alerts (
        finding_pk INTEGER NOT NULL REFERENCES findings(finding_pk),
        alert_pk INTEGER NOT NULL REFERENCES alerts(alert_pk),
        position INTEGER NOT NULL CHECK (position >= 0),
        PRIMARY KEY (finding_pk, alert_pk),
        UNIQUE (finding_pk, position)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS finding_events (
        finding_pk INTEGER NOT NULL REFERENCES findings(finding_pk),
        event_pk INTEGER NOT NULL REFERENCES normalized_events(event_pk),
        position INTEGER NOT NULL CHECK (position >= 0),
        PRIMARY KEY (finding_pk, event_pk),
        UNIQUE (finding_pk, position)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_normalized_events_timestamp ON normalized_events(timestamp)",
    "CREATE INDEX IF NOT EXISTS ix_normalized_events_source_ip ON normalized_events(source_ip)",
    "CREATE INDEX IF NOT EXISTS ix_normalized_events_username ON normalized_events(username)",
    "CREATE INDEX IF NOT EXISTS ix_alerts_timestamp ON alerts(timestamp)",
    "CREATE INDEX IF NOT EXISTS ix_alerts_source_ip ON alerts(source_ip)",
    "CREATE INDEX IF NOT EXISTS ix_findings_timestamp ON findings(timestamp)",
    "CREATE INDEX IF NOT EXISTS ix_findings_severity ON findings(severity)",
    "CREATE INDEX IF NOT EXISTS ix_findings_finding_type ON findings(finding_type)",
    "CREATE INDEX IF NOT EXISTS ix_findings_source_ip ON findings(source_ip)",
)


def connect(database: str) -> sqlite3.Connection:
    """Open a SQLite connection with row access by name and FK enforcement on.

    SQLite does not enforce declared FOREIGN KEY constraints unless this
    pragma is set on every connection.
    """
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Create the persistence schema if missing. Safe to call repeatedly."""
    with connection:
        for statement in _SCHEMA_STATEMENTS:
            connection.execute(statement)
