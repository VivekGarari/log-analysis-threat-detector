# Log Analysis & Threat Detection Tool

A Python-based security log analysis and threat detection system designed to ingest heterogeneous security logs, normalize them into common security semantics, detect suspicious activity, and produce evidence-backed alerts.

## Status

🚧 Under active development.

The core end-to-end detection pipeline is operational and regression-tested. Current development is focused on hardening the detection architecture before adding persistence, dashboards, and additional detection capabilities.

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
DetectionPipeline
   ↓
DetectionEngine
   ↓
Detection Rules
   ↓
Alert[]
   ↓
Reporter
   ├── Human-readable text
   └── JSON
   ↓
CLI stdout
```

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

Supports Apache Combined Log Format access records and normalizes them into HTTP access events.

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
└── service
```

The canonical timestamp is timezone-aware and normalized to UTC.

`event_type` represents the common security meaning of an event, while `source` identifies the ingestion origin and `service` represents service/protocol semantics.

Source-specific fields that are not currently required by common detection logic remain in their format-specific event models.

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

## CLI

The current application can process supported log formats through the command line.

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

Linux authentication logs additionally require an explicit timezone-aware reference timestamp because the source format does not contain a year.

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

The current suite contains **140 passing tests**.

Detection behavior that is important to the system is covered by regression tests and documented in the project documentation.

## Project Documentation

Detailed engineering and behavioral documentation is maintained separately from this overview.

* [`Detection Rule Semantics`](docs/detection-rules.md) — stateful detection windows, watermark behavior, grouping, duplicate handling, suppression, expiration, and out-of-order events.
* [`Alert Semantics`](docs/alert-semantics.md) — detection snapshots, timestamp meaning, deterministic identity, rule suppression, and deferred persistence decisions.
* [`Detection Engine and Pipeline`](docs/detection-engine.md) — dispatch order, fail-fast errors, parser misses, and continuing stream state.

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
* Persistence
* Security-focused dashboards

Features will be added only after the underlying contracts are sufficiently well-defined and tested.
