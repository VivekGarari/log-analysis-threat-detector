# Log Analysis & Threat Detection Tool

A Python security log analysis and threat detection application that parses supported security logs, normalizes records into common security semantics, detects suspicious activity, correlates related evidence, and persists investigation Findings.

## Overview

The application ingests heterogeneous security logs, applies format-specific parsers and normalizers, runs stateful and stateless detection rules, and correlates selected activity into evidence-backed Findings. Alerts are immediate rule results. Findings are higher-level investigation results persisted in SQLite and exposed through a read-only investigation API.

## Release Status

**Phase 8 released — detection and investigation core frozen.**

The detection pipeline, correlation, SQLite persistence, and read-only investigation API are operational. The released security-analysis core has undergone security hardening. This release is a backend/security-analysis application with CLI and API interfaces, not a polished end-user dashboard or hosted service. A customer-facing dashboard, browser-based log upload, continuous ingestion, deployment packaging, authentication, multi-user support, and operational monitoring are future product-layer work that would be scoped separately from the frozen core.

## What This Release Is

The current release consists of three cooperating parts:

* **Detection and investigation engine:** parses and normalizes supported records, evaluates detection rules, correlates selected Alerts and events, and builds Findings.
* **CLI:** processes one log file per invocation and prints the resulting Alerts as text or JSON.
* **Investigation API:** provides read-only access to persisted Findings and their investigation views.

A current user supplies a supported log file to the CLI and investigates any generated Findings through the API. A future web dashboard or other customer-facing interface can sit above the investigation API without coupling presentation concerns to detection logic.

## Key Capabilities

* Ingestion and format-specific parsing for Linux authentication logs, Windows Security XML events, and Apache Combined access logs.
* A canonical `NormalizedEvent` model for common security semantics.
* Stateful and stateless detection, with deterministic event-time behavior.
* Correlation into evidence-backed Findings, separate from instantaneous Alerts.
* SQLite persistence for Findings and their contributing evidence relationships.
* A read-only `FindingView` investigation projection and API.
* Text and JSON Alert reporting, with automated regression coverage and release security hardening.

## Architecture

```text
Raw Log
   |
Parser
   |
Format-Specific Event
   |
Normalizer
   |
NormalizedEvent
   |
DetectionEngine
   |
Alert[]
   |
CorrelationEngine(NormalizedEvent, Alert[])
   |
Finding[]
   |
process_and_persist()
   |
SQLite
   |
Investigation Service/API
   |
FindingView
```

The parser recognizes source-specific records; the normalizer maps them to common fields. The detection engine applies rules to each normalized event, and the correlation engine evaluates supported relationships between Alerts and events. `process_and_persist()` stores produced Findings and their contributing evidence. The investigation service rebuilds a `FindingView` from persisted data for API clients.

Everything before `NormalizedEvent` is primarily concerned with log format and source representation. Everything after it is concerned with common security semantics and detection behavior. Detection rules therefore do not parse raw log formats.

## Supported Log Sources

Only the following sources are currently implemented:

1. **Linux Authentication Logs:** SSH authentication success, authentication failure, and invalid-user records.
2. **Windows Security Events:** Event ID `4624` (authentication success) and `4625` (authentication failure).
3. **Apache Access Logs:** Apache Combined Log Format access records, normalized as HTTP access events with the request path available as `http_path`.

## Normalized Event Model

The canonical model currently contains these fields:

```text
NormalizedEvent
├── timestamp
├── source
├── event_type
├── hostname
├── username
├── source_ip
├── source_port
├── success
├── raw
├── service
└── http_path
```

`timestamp` is timezone-aware and normalized to UTC. `event_type` carries common security meaning, `source` identifies the ingestion origin, and `service` represents service/protocol semantics. `http_path` carries the normalized HTTP request path used by web reconnaissance detection. Detection rules operate on these structured normalized fields rather than parsing `raw` log text.

## Detection Rules

The stateful rules use event timestamps and a 60-second window. The boundary is inclusive; each rule advances a watermark to the greatest event timestamp it has observed. Events older than the active watermark cutoff are ignored. State expires as the watermark advances, not on a wall-clock timer. Out-of-order events can be accepted while they remain within the active window.

### SSH Brute Force

Five qualifying `authentication_failure` events with `service == "ssh"` from one non-null source IP trigger a high-severity Alert within the inclusive 60-second window. The source IP is the grouping key; username does not affect the count, and duplicate failures count independently. Further alerts for that IP are suppressed while active state remains at or above threshold. Expiration below threshold clears suppression, so a later threshold crossing can alert again.

### Invalid User

This rule is stateless: each matching `invalid_user` event produces an Alert. It has no event-time window, watermark expiration, or suppression state.

### Password Spraying

Five distinct usernames from one source IP within the inclusive 60-second window trigger an Alert. Both `authentication_failure` and `invalid_user` events qualify. Repeated attempts for the same username do not increase the count. State is grouped by source IP; expiration removes usernames and can clear suppression below threshold. Expired usernames do not contribute to a later alert.

### Web Reconnaissance

This rule evaluates HTTP access events with `service == "http"`, a source IP, and an HTTP path. Five distinct suspicious paths from one source IP within the inclusive 60-second window trigger a medium-severity Alert. Before matching, the query string is stripped and the path is lowercased; repeated paths after this normalization do not increase the count. The V1 signature covers representative administrative and CMS paths, exposed configuration or version-control files, status endpoints, CGI paths, backups/database files, and shell/webshell probes. Method and status code are not part of the V1 logic.

As with other stateful rules, further alerts are suppressed while active state remains at threshold or above, and expiration below threshold allows a later alert. Alert identity, evidence, and raw event evidence use the same sorted normalized-path order. The curated signature is heuristic, not a comprehensive scanner: it can miss probes outside its signatures and can flag legitimate administration. V1 does not normalize percent-encoding or path-traversal sequences, and deployments behind a reverse proxy group on the logged proxy IP.

Exact behavioral contracts, including grouping, suppression, expiration, and out-of-order handling, are in [`docs/detection-rules.md`](docs/detection-rules.md).

## Alerts

An Alert is an instantaneous detection result, not a lifecycle-managed incident. It contains a deterministic rule-generated Alert identity, rule identity, severity, title and description, triggering-event timestamp, source IP, username where applicable, human-readable evidence, and raw-event evidence. Alert IDs are not guaranteed globally unique and are not database primary keys.

The reporting layer supports **text** and **JSON**. The CLI prints Alerts only; it does not currently print Findings.

## Correlation and Findings

The correlation engine implements two explicit scenarios:

1. **Credential attack followed by successful SSH authentication:** an `ssh_brute_force` Alert followed strictly later by an `authentication_success` event with `service == "ssh"` from the same source IP produces a `credential_attack_success` Finding. The event-time gap may be at most 180 seconds (inclusive). Username matching is not required; the successful event supplies the Finding username and timestamp.
2. **Web reconnaissance followed by password spraying:** a `web_reconnaissance` Alert followed strictly later by a `password_spraying` Alert from the same source IP within 180 seconds produces a `reconnaissance_credential_attack` Finding. This represents source-IP and temporal co-occurrence only. It does not establish causation, a single attacker, successful authentication, or compromise.

A Finding is an additive, higher-level investigation result built from contributing evidence; it is distinct from the Alert emitted by a rule. The first scenario is an elevated compromise-risk signal, not proof of compromise. The second has weaker co-occurrence evidence, as described above. See [`docs/correlation.md`](docs/correlation.md) for exact event-time, selection, identity, and evidence semantics.

## Persistence

SQLite persistence uses Python's standard-library `sqlite3`; the project does not use an ORM. The schema creates five tables: `normalized_events`, `alerts`, `findings`, `finding_alerts`, and `finding_events`. Link-table positions preserve contributor order. `FindingView` is a read-only projection and is rebuilt from a Finding; it is not stored.

On the CLI path, generated Findings and their contributing Alerts and NormalizedEvents are persisted as a graph in an atomic batch transaction. The CLI does not independently persist every processed event or every Alert. Replaying the same logical objects creates new rows with new surrogate keys; V1 does not deduplicate ingestion. See [`docs/persistence.md`](docs/persistence.md) for schema and replay details.

Database path precedence is:

1. CLI `--database` option.
2. `THREAT_DETECTOR_DATABASE` environment variable.
3. `threat_detector.sqlite3` in the process working directory.

The CLI and API must point to the same SQLite file to share investigation data. The API reads persisted investigation data; its startup initializes the schema.

## Investigation API

The read-only FastAPI investigation API is the current interface for persisted Findings. Install the project as described below, then start the server bound to loopback:

```powershell
python -m uvicorn threat_detector.api.app:app --host 127.0.0.1 --port 8000
```

Set `THREAT_DETECTOR_DATABASE` to the same path used by the CLI before starting the API. The API initializes its schema on startup. Interactive OpenAPI documentation is available at `http://127.0.0.1:8000/docs`.

### `GET /findings`

Lists persisted Finding summaries. Supported query parameters are:

* `severity`: exact match; `high` or `critical`.
* `finding_type`: exact match; `credential_attack_success` or `reconnaissance_credential_attack`.
* `source_ip`: exact match.
* `from_timestamp`: timezone-aware ISO-8601 inclusive lower bound.
* `to_timestamp`: timezone-aware ISO-8601 exclusive upper bound.
* `limit`: page size from 1 to 100; default 50.
* `cursor`: opaque continuation value from the previous response's `next_cursor`.

Results are ordered by timestamp descending and then persisted `finding_pk` descending. Pagination is keyset-based and does not return a total count. For example:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/findings?source_ip=192.0.2.77&limit=10"
```

### `GET /findings/{finding_pk}`

Retrieves a specific Finding by its positive persisted integer `finding_pk` (the list response's `id`). The response provides Finding-view metadata, entities, timeline entries, and evidence. It omits raw events and raw normalized-event content. For example, replace `1` with an `id` returned by the list endpoint:

```powershell
$findingPk = 1
Invoke-RestMethod -Uri "http://127.0.0.1:8000/findings/$findingPk"
```

Invalid filters, timestamps, ranges, page sizes, cursors, or IDs return `422`; a missing valid ID returns `404`. A valid empty list query returns `200` with no items. The API has no authentication or authorization in this release. Keep it bound to loopback; do not expose it to untrusted networks. See [`docs/investigation-api.md`](docs/investigation-api.md) for the full response and error contract.

## How to Use

### 1. Install and prepare the environment

Python `3.12` or newer is required. The project declares runtime dependencies and the optional test dependencies in `pyproject.toml`.

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
```

The editable install includes the FastAPI and Uvicorn runtime dependencies, plus the optional `pytest` and `httpx` test dependencies. To install runtime dependencies only, use `python -m pip install -e .`.

### 2. Analyze one log file

The CLI processes one input file per invocation. Its general form is:

```powershell
python -m threat_detector.cli --input <file> --format <format> --output <output>
```

Supported input formats are `linux-auth`, `windows-security`, and `apache-access`. Supported output formats are `text` and `json`; output defaults to `text` when `--output` is omitted. `--database <path>` selects the SQLite file for generated Findings. `--help` displays the supported options.

`linux-auth` requires `--reference-time`, a timezone-aware ISO-8601 timestamp. Linux syslog records do not include a year; the reference timestamp supplies it. For example:

```powershell
python -m threat_detector.cli --input .\auth.log --format linux-auth --reference-time 2026-10-02T12:00:00+00:00 --output text
```

### 3. Safe synthetic Linux example

Create a small synthetic log. The source address is from the documentation-only `192.0.2.0/24` range and the username is fictitious:

```powershell
@'
Oct  2 11:59:55 demo-host sshd[1001]: Failed password for example-user from 192.0.2.77 port 41001 ssh2
Oct  2 11:59:56 demo-host sshd[1002]: Failed password for example-user from 192.0.2.77 port 41002 ssh2
Oct  2 11:59:57 demo-host sshd[1003]: Failed password for example-user from 192.0.2.77 port 41003 ssh2
Oct  2 11:59:58 demo-host sshd[1004]: Failed password for example-user from 192.0.2.77 port 41004 ssh2
Oct  2 11:59:59 demo-host sshd[1005]: Failed password for example-user from 192.0.2.77 port 41005 ssh2
Oct  2 12:00:03 demo-host sshd[1006]: Accepted password for example-user from 192.0.2.77 port 41006 ssh2
'@ | Set-Content -Path .\sample-auth.log -Encoding ASCII
```

Run the CLI with a timezone-aware reference time and an explicit local database path:

```powershell
python -m threat_detector.cli --input .\sample-auth.log --format linux-auth --reference-time 2026-10-02T12:00:00+00:00 --output text --database .\threat_detector.sqlite3
```

The five failures produce an Alert similar to this excerpt (the complete text report also includes all evidence and raw events):

```text
Alert
rule_id: ssh_brute_force
severity: high
title: SSH brute-force attack detected
description: At least 5 SSH authentication failures were observed from 192.0.2.77 within 60 seconds.
timestamp: 2026-10-02T11:59:59+00:00
source_ip: 192.0.2.77
username: example-user
```

This Alert is the immediate detection result printed by the CLI. The later successful SSH authentication from the same source IP is within 180 seconds, so it also produces a correlated Finding. The CLI persists that Finding and its contributing evidence to SQLite; it does not print the Finding.

### 4. Investigate persisted Findings

In the same PowerShell session, configure the API to read the database path used above, then start the API:

```powershell
$env:THREAT_DETECTOR_DATABASE = Join-Path (Get-Location) "threat_detector.sqlite3"
python -m uvicorn threat_detector.api.app:app --host 127.0.0.1 --port 8000
```

In another terminal, list Findings for the synthetic source address and use a returned `id` to request its detail:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/findings?source_ip=192.0.2.77&limit=10"
$findingPk = 1  # Replace 1 with an id returned by the list request.
Invoke-RestMethod -Uri "http://127.0.0.1:8000/findings/$findingPk"
```

## Typical Workflow

```text
Log File
   |
CLI
   |
Parser
   |
Normalizer
   |
Detection
   |
Correlation
   |
Finding
   |
SQLite
   |
Investigation API
   |
Analyst / Developer
```

This is the workflow supported by the current release: the CLI prints Alerts, generated Findings and their contributing evidence are persisted, and the read-only API serves the investigation view.

## Security and Release Hardening

Phase 8 included security hardening of the released core. Implemented safeguards include finite CLI processing and report budgets, terminal-control escaping in text reports, bounded API pagination and query validation, generic responses for unexpected SQLite errors, and API detail responses that exclude raw log content. These safeguards reduce specific risks; they are not a claim of universal production security or a substitute for deployment review.

The documented deployment boundary is local investigation: the API has no authentication or authorization and should remain bound to loopback rather than be exposed to untrusted networks. Network deployment, identity controls, operational monitoring, and other environment-specific protections remain deployment or future product-layer concerns.

## Testing

The released repository's automated suite has **309 passing tests**. Run it with:

```powershell
python -m pytest
```

Regression coverage includes parsers, normalizers, detection rules and engine behavior, correlation, application processing and resource limits, SQLite persistence, investigation projections and API behavior, reporting, CLI behavior, and fixture-based end-to-end detection for supported sources.

## Project Documentation

The current engineering and behavior documents are:

* [`docs/detection-rules.md`](docs/detection-rules.md) — thresholds, windows, grouping, suppression, expiration, and out-of-order semantics.
* [`docs/alert-semantics.md`](docs/alert-semantics.md) — Alert identity, timestamps, suppression, and the distinction from Findings.
* [`docs/correlation.md`](docs/correlation.md) — supported correlation scenarios, evidence, event-time behavior, and limitations.
* [`docs/persistence.md`](docs/persistence.md) — SQLite schema, identity, transactions, and replay behavior.
* [`docs/investigation-api.md`](docs/investigation-api.md) — read-only endpoints, filters, pagination, responses, and deployment boundary.
* [`docs/detection-engine.md`](docs/detection-engine.md) — detection dispatch and pipeline behavior.
* [`docs/cli-and-reporting.md`](docs/cli-and-reporting.md) — CLI/reporting contracts and processing resource limits.

## Development Principles

1. **Separate parsing from security semantics.**
2. **Keep detection rules independent of log-format details.**
3. **Use explicit contracts between pipeline stages.**
4. **Prefer deterministic behavior and regression tests.**
5. **Document architectural and behavioral decisions.**
6. **Avoid premature architectural complexity.**
7. **Treat detection semantics as contracts that should not change accidentally.**

## Future Direction

The security-analysis core is frozen at this release boundary. Separately scoped future product work could build on it with a web security dashboard, browser-based log upload, continuous ingestion, additional detection capabilities, deployment and packaging, authentication and multi-user support, or operational monitoring. These are future possibilities, not capabilities of the current release.
