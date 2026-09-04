# CLI and Reporting

This document records the current boundary between the command-line interface, the detection pipeline, and the two reporters.

## CLI Contract

The CLI creates a fresh format-specific pipeline and detection engine for each invocation. It processes the selected input format, collects the resulting `Alert` objects, and sends the same alert list to the selected reporter.

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

Text output is intended for human-readable analysis rather than lossless interchange. It preserves alert order and displays alert IDs, rule information, descriptions, timestamps, source fields, evidence, and raw events.

Missing scalar values and empty lists are displayed as `N/A`. JSON should be used when machine-readable distinction between null, empty collections, and textual values is required.