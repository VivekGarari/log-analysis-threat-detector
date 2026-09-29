# CLI and Reporting

This document records the current boundary between the command-line interface, the producer workflow, and the two Alert reporters.

## CLI Contract

The CLI accepts one input file per invocation and creates a fresh format-specific pipeline and detection engine for it. The producer workflow is:

```text
Input log
 → parser/normalizer
 → DetectionEngine
 → Alert[]
 → CorrelationEngine(NormalizedEvent, Alert[])
 → Finding[]
 → process_and_persist()
 → SQLite
```

The reporters still render `Alert` objects, not Findings. Existing text and JSON outputs remain Alert-based: JSON serialization is unchanged, and the text reporter visibly escapes non-printing characters in raw-event evidence. When correlation produces Findings, `process_and_persist()` stores them in SQLite. Findings are not currently printed by the CLI; the investigation API is the query and investigation interface.

The `--database` option selects the Findings database. Database path precedence is explicit `--database`, then `THREAT_DETECTOR_DATABASE`, then `threat_detector.sqlite3`. Relative paths depend on the process working directory.

Successful processing returns exit code `0`, whether alerts exist or the result is empty. A zero-alert JSON result is the valid JSON value `[]`.

Argument errors and invalid input paths use `argparse` error handling and exit with code `2`. Processing failures, including normalizer, detection-rule, and reporter failures, are written as `error: ...` to stderr and return exit code `1`.

Parser misses are expected non-events. They are skipped by the pipeline, so an input containing only parser misses can complete successfully with no alerts.

Successful output is written to stdout. Runtime errors are written to stderr. The CLI does not reorder or mutate alerts; output ordering comes from pipeline event order and engine rule registration order.

## JSON Output

JSON is the machine-readable representation. It preserves the complete current `Alert` schema:

* alert ID, rule ID, severity, title, and description
* ISO-8601 timestamp
* nullable source IP and username
* evidence and raw event arrays

`None` values become JSON `null`, lists remain JSON arrays, and alert order is preserved. An empty alert list serializes as `[]`.

## Text Output

Text output is intended for human-readable analysis rather than lossless interchange. It preserves alert and raw-event order and displays alert IDs, rule information, descriptions, timestamps, source fields, evidence, and raw events. Non-printing characters in raw events are escaped for terminal safety; ordinary printable text remains readable.

Missing scalar values and empty lists are displayed as `N/A`. JSON should be used when machine-readable distinction between null, empty collections, and textual values is required.