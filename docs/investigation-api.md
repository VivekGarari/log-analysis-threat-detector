# Investigation API

The read-only FastAPI boundary provides access to persisted findings for local investigation clients. It does not expose database rows or raw log data.

## Run Locally

Install the project and its runtime dependencies, then run the server bound to loopback:

```powershell
python -m pip install -e .
python -m uvicorn threat_detector.api.app:app --host 127.0.0.1 --port 8000
```

The default database path is `threat_detector.sqlite3` in the current working directory. Set `THREAT_DETECTOR_DATABASE` to use another SQLite file. The API initializes its schema on startup. OpenAPI documentation is available at `/docs` while the server is running.

The CLI processes Linux, Windows, and Apache logs through detection and correlation, and persists produced Findings with their contributing Alerts and Events. Set `THREAT_DETECTOR_DATABASE` for both the CLI and API to share a database, or pass `--database PATH` to the CLI and configure the API with the same path. The CLI creates/initializes the database only when processing produces Findings; its existing Alert report output is unchanged.

## Endpoints

### `GET /findings`

Returns a page of finding summaries:

```json
{
  "items": [
    {
      "id": 12,
      "finding_id": "credential_attack_success:...",
      "finding_type": "credential_attack_success",
      "severity": "critical",
      "title": "Credential attack followed by successful SSH authentication",
      "timestamp": "2026-01-01T00:00:00+00:00",
      "source_ip": "192.0.2.10",
      "username": "root"
    }
  ],
  "next_cursor": null
}
```

The `id` is the persisted `finding_pk` and is the resource identifier. `finding_id` remains a domain identity and can repeat when a logical finding is replayed; it must not be used to retrieve an individual row.

Optional query parameters:

* `severity`: exact match; supported values are `high` and `critical`.
* `finding_type`: exact match; supported values are `credential_attack_success` and `reconnaissance_credential_attack`.
* `source_ip`: exact match.
* `from_timestamp`: timezone-aware ISO-8601 lower bound, inclusive.
* `to_timestamp`: timezone-aware ISO-8601 upper bound, exclusive.
* `limit`: page size from 1 through 100; defaults to 50.
* `cursor`: opaque continuation value returned by the previous page.

Timestamp filters are normalized to UTC and retain microsecond precision. If both bounds are supplied, `from_timestamp` must be earlier than `to_timestamp`. Results are ordered by `timestamp DESC, finding_pk DESC`; pagination is keyset-based and does not calculate a total count. Request the next page by passing `next_cursor` as `cursor`.

### `GET /findings/{id}`

Returns the finding view for the exact persisted `finding_pk`. The response contains FindingView-equivalent metadata, entities, timeline entries, and evidence. Timestamps are ISO-8601. The response does not include `finding_pk`, alert/event persistence keys, `raw_events`, or raw normalized event content.

## Errors

Invalid filters, timestamps, ranges, limits, cursors, or detail `finding_pk` values outside the positive signed 64-bit SQLite integer range return `422`. A missing in-range `finding_pk` returns `404`. A valid list query with no matches returns `200` with `items: []` and `next_cursor: null`. Unexpected SQLite failures return a generic `500` response without database or exception details.

This MVP has no authentication or authorization layer. Keep the development server bound to loopback and do not expose it to untrusted networks.