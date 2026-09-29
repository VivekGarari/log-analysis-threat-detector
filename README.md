# Log Analysis & Threat Detection Tool

A Python-based security log analysis and threat detection system designed to ingest heterogeneous security logs, normalize them into common security semantics, detect suspicious activity, and produce evidence-backed alerts.

## Status

🚧 Under active development.

The detection pipeline, investigation projection, SQLite persistence, and read-only investigation API are operational.

## Goal

Build a modular security log analysis and threat detection system that can:

* Ingest logs from multiple security-relevant sources.
* Parse format-specific log records.
* Normalize different log formats into a common security event model.
* Detect suspicious behavior using stateful and stateless detection rules.
* Correlate activity across supported log sources where appropriate.
* Produce human-readable and machine-readable security alerts.
* Provide sufficient evidence to understand why an alert was generated.

## Architecture

```text
Raw Log
   ↓
Parser
   ↓
Format-Specific Event
   ↓
Normalizer
   ↓
NormalizedEvent
   ↓
DetectionEngine
   ↓
Alert[]
   ↓
CorrelationEngine(NormalizedEvent, Alert[])
   ↓
Finding[]
   ↓
process_and_persist()
   ↓
SQLite
   ↓
Investigation Service/API
   ↓
FindingView
   ↓
GET /findings
GET /findings/{finding_pk}
```

The CLI sends `Alert[]` to the text or JSON reporter and prints that Alert output. Findings are persisted, but are not printed by the CLI; the investigation API is the interface for querying them.

### Core Design Principle

Everything before `NormalizedEvent` is concerned primarily with **log format and source-specific representation**.

Everything after `NormalizedEvent` is concerned with **common security semantics and detection behavior**.

This separation allows detection rules to operate across different log sources without knowing the details of individual log formats.

## Supported Log Sources

### Linux Authentication Logs

Supports SSH-related authentication activity including:

* Successful authentication
* Failed authentication
* Invalid users

### Windows Security Events

Currently supports:

* Event ID `4624` — authentication success
* Event ID `4625` — authentication failure

### Apache Access Logs

Supports Apache Combined Log Format access records and normalizes them into HTTP access events. The request path is preserved as `http_path` in the canonical event model for use by detection rules.

## Normalized Event Model

The current canonical event model is:

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

The canonical timestamp is timezone-aware and normalized to UTC.

`event_type` represents the common security meaning of an event, while `source` identifies the ingestion origin and `service` represents service/protocol semantics.

Source-specific fields that are not currently required by common detection logic remain in their format-specific event models.

`http_path` is populated by the Apache access log normalizer and is available to detection rules for web reconnaissance detection.

## Current Detection Rules

### SSH Brute Force

Detects repeated SSH authentication failures from a single source IP.

Current contract:

* Threshold: 5 qualifying failures
* Window: 60 seconds
* Window boundary: inclusive
* Grouping: source IP
* Duplicate failures count independently
* Username does not affect counting
* One alert is emitted per active attack window and source IP

### Invalid User

Detects attempts involving an invalid username.

This rule is stateless and produces an alert for each matching event.

### Password Spraying

Detects authentication activity targeting multiple usernames from a single source IP.

Current contract:

* Threshold: 5 distinct usernames
* Window: 60 seconds
* Grouping: source IP
* Repeated attempts for the same username do not increase the distinct-user count
* Both `authentication_failure` and `invalid_user` events qualify
* One alert is emitted per active attack window and source IP

### Web Reconnaissance

Detects web reconnaissance and probing activity from a single source IP by identifying requests for multiple distinct suspicious HTTP paths within a short time window.

Current contract:

* Threshold: 5 distinct suspicious paths
* Window: 60 seconds
* Grouping: source IP
* Repeated requests for the same suspicious path do not increase the distinct-path count
* Path normalization strips query strings before matching; case is normalized
* Suspicious paths are identified by a curated V1 signature (administrative interfaces, CMS admin paths, config/secrets files, version control metadata, server status endpoints, CGI paths, backup/database files, and shell/webshell probes)
* Alerts are suppressed while the source IP remains at threshold or above; suppression clears when expiration reduces active state below threshold, allowing a later re-alert
* Alert identity, evidence, and raw event evidence use the same sorted normalized-path order
* Severity: medium

Detailed detection contracts are documented in [`docs/detection-rules.md`](docs/detection-rules.md).

## Alerting

Alerts currently contain:

* Alert identity
* Detection rule identity
* Severity
* Title and description
* Timestamp
* Source IP
* Username where applicable
* Human-readable evidence
* Raw event evidence

The reporting layer currently supports:

* Human-readable text
* JSON

Alerts are instantaneous detection results. Findings are separate correlation results that combine structured alert and normalized-event evidence. V1 correlates an SSH brute-force alert with a later successful SSH authentication from the same source IP within an inclusive 180-second event-time window. A second scenario correlates a web-reconnaissance alert with a later password-spraying alert from the same source IP within the same 180-second window; this Finding reflects source-IP and temporal co-occurrence only and does not claim causation, a single attacker, or successful authentication. See [`docs/correlation.md`](docs/correlation.md) for the exact semantics and limitations.

## CLI

The CLI processes one input file per invocation and supports the listed log formats and Alert output formats.

General form:

```text
python -m threat_detector.cli --input <file> --format <format> --output <output>
```

Supported formats:

```text
linux-auth
windows-security
apache-access
```

Supported outputs:

```text
text
json
```

`--format linux-auth` requires `--reference-time` with a timezone-aware ISO-8601 timestamp because the source format does not contain a year.

Generated Findings are persisted to SQLite. Database path precedence is `--database`, then `THREAT_DETECTOR_DATABASE`, then `threat_detector.sqlite3` in the process working directory. Relative paths are resolved from that working directory.

## Testing

The project has an automated regression suite covering:

* Parsers
* Normalizers
* Detection rules
* Detection engine
* Application pipeline
* Reporting
* CLI behavior
* End-to-end fixture-based detection

The current suite contains **265 passing tests**.

Detection behavior that is important to the system is covered by regression tests and documented in the project documentation.

## Project Documentation

Detailed engineering and behavioral documentation is maintained separately from this overview.

* [`Detection Rule Semantics`](docs/detection-rules.md) — stateful detection windows, watermark behavior, grouping, duplicate handling, suppression, expiration, and out-of-order events.
* [`Alert Semantics`](docs/alert-semantics.md) — detection snapshots, timestamp meaning, deterministic identity, rule suppression, and downstream Finding semantics.
* [`Detection Engine and Pipeline`](docs/detection-engine.md) — dispatch order, fail-fast errors, parser misses, and continuing stream state.
* [`Correlation Semantics`](docs/correlation.md) — the V1 credential attack success scenario and the reconnaissance-to-credential-attack scenario, event-time state, evidence, and deterministic identity.
* [`Persistence`](docs/persistence.md) — the SQLite schema, identity strategy, and replay behavior for storing NormalizedEvents, Alerts, and Findings.
* [`Investigation API`](docs/investigation-api.md) — read-only finding endpoints, filters, timestamp behavior, pagination, and response boundaries.

Additional documentation will be added as the architecture develops.

## Development Principles

The project currently follows several core principles:

1. **Separate parsing from security semantics.**
2. **Keep detection rules independent of log-format details.**
3. **Use explicit contracts between pipeline stages.**
4. **Prefer deterministic behavior and regression tests.**
5. **Document important architectural and behavioral decisions.**
6. **Avoid premature architectural complexity.**
7. **Treat detection semantics as contracts that should not change accidentally.**

## Current Development Direction

The immediate priority is to harden the existing detection architecture before expanding the system.

Planned areas include:

* Alert identity and lifecycle
* Detection-state hardening
* Configuration
* CLI usability
* Additional serious detection capabilities
* Security-focused dashboards

Features will be added only after the underlying contracts are sufficiently well-defined and tested.
