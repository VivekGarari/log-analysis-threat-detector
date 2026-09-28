# Persistence (Phase 5)

## Scope

`threat_detector.persistence` is a SQLite-backed storage layer for `NormalizedEvent`, `Alert`, and `Finding`. Application orchestration persists produced Findings through the repository after detection and correlation; detection and correlation remain persistence-independent. `FindingView` is never persisted — it is always rebuilt from a `Finding` via `build_finding_view`.

## Technology

Plain stdlib `sqlite3`, no ORM. `threat_detector.persistence.schema.connect()` opens a connection with `row_factory = sqlite3.Row` and executes `PRAGMA foreign_keys = ON`, which SQLite requires on every connection to actually enforce declared foreign keys.

## Schema

Six objects, created by `initialize_schema()` (idempotent `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`, safe to call repeatedly):

* `normalized_events` — one row per persisted `NormalizedEvent`, surrogate `event_pk`.
* `alerts` — one row per persisted `Alert`, surrogate `alert_pk`. `alert_id` is stored as a plain (non-unique) indexed-by-nothing domain identity column, consistent with it not being guaranteed globally unique.
* `findings` — one row per persisted `Finding`, surrogate `finding_pk`. `finding_id` is likewise a non-unique domain identity column.
* `finding_alerts` / `finding_events` — many-to-many link tables between `findings` and `alerts`/`normalized_events`, each with a `position` column that preserves the exact order of `Finding.contributing_alerts` / `Finding.contributing_events`.

Timestamps are stored as timezone-aware UTC ISO-8601 text and round-trip through `datetime.fromisoformat()` without losing timezone information. `success` is stored as `1`/`0`/`NULL` for `True`/`False`/`None`. `evidence` and `raw_events` are stored as JSON-encoded arrays in `TEXT` columns and decoded back into tuples/lists on load.

Indexes exist only where a stated investigation need exists today: `timestamp`/`source_ip`/`username` on `normalized_events`; `timestamp`/`source_ip` on `alerts`; `timestamp`/`severity`/`finding_type`/`source_ip` on `findings`.

## API

`threat_detector.persistence` exposes: `connect`, `initialize_schema`, `save_normalized_event`/`load_normalized_event`, `save_alert`/`load_alert`, `save_finding`/`load_finding`. There is no generic repository/ORM abstraction — each function is a small, explicit read or write.

`save_finding` persists the `Finding` row, its contributing `Alert`s and `NormalizedEvent`s, and both link tables' `position`-ordered rows inside a single transaction (`with connection:`); any failure rolls back the entire graph, so a `Finding` is never left partially persisted. `load_finding` reconstructs the exact `Finding` shape — including `contributing_alerts`/`contributing_events` in original order — from which `build_finding_view()` works unchanged.

## Replay Behavior

Saving the same logical `Alert`/`Finding`/`NormalizedEvent` twice creates separate rows (new surrogate keys); there is no ingestion-level deduplication in V1. This is intentional — see the Phase 5 design audit for the reasoning.
