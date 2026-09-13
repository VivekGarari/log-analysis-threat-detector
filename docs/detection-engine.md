# Detection Engine and Pipeline

This document records the current contracts for event dispatch and pipeline sequencing. It describes existing behavior and does not define reset, persistence, or exception-isolation APIs.

## DetectionEngine

`DetectionEngine` receives an iterable of detection-rule instances and materializes it in registration order.

For each normalized event:

* Every registered rule instance receives the event once for each registration.
* Rules are invoked in registration order.
* A rule may return one `Alert` or `None`.
* `None` results are filtered out.
* Returned alerts preserve rule registration order.
* The engine does not sort, buffer, deduplicate, or otherwise transform events or alerts.

An empty rule set returns an empty alert list. The engine currently does not enforce unique rule IDs or unique rule instances. All registered instances are dispatched in registration order. Duplicate registration is therefore a caller configuration concern and is not recommended merely because it is allowed.

### Fail-Fast Exceptions

DetectionEngine processing is fail-fast per event. If a rule raises, the exception propagates and later rules do not receive that event. The engine does not provide transactional rollback. Earlier rules may already have processed the event and changed their own state before the failure.

The engine does not provide exception isolation or continue-on-error behavior.

## DetectionPipeline

`DetectionPipeline.process()` accepts an iterable of raw records, normally raw log lines. It applies the stages in this order:

```text
raw record
→ parser
→ parsed event or None
→ normalizer
→ NormalizedEvent
→ DetectionEngine
→ collected alerts
→ CorrelationEngine (when configured)
→ collected findings
```

The pipeline owns this parser-to-normalizer-to-engine sequencing:

* A parser returning `None` means the record is a parser miss, not an exception.
* Parser misses skip normalization and engine processing for that record.
* Later valid records continue processing after a parser miss.
* Normalizer failures propagate and the engine is not called for that failed record.
* Engine failures propagate to the caller.
* Empty input and input containing only parser misses produce an empty alert list.

The pipeline does not sort, buffer, deduplicate, or duplicate records. Input order is preserved through normalization and engine processing. Alerts preserve input event order, and alerts from one event preserve engine rule registration order.

`DetectionPipeline.process()` continues to return `list[Alert]` for compatibility. A pipeline configured with a `CorrelationEngine` can use `process_with_findings()` to receive a `ProcessingResult` containing both `alerts` and `findings`. Correlation occurs immediately after detection for each normalized event.

## Ordering

The current ordering contract is:

```text
input order
    ↓
normalization order
    ↓
engine event-processing order
    ↓
rule registration order
    ↓
alert output order
```

Stateful rules receive events exactly once in the supplied order. Event-time interpretation, watermark handling, and state expiration remain responsibilities of the rules themselves; the pipeline does not sort or buffer events for them.

## Stream Lifecycle

An engine or pipeline instance represents a continuing logical event stream. Stateful detection state persists across repeated `process()` calls.

For example, events below a stateful rule threshold supplied in one call can combine with later events supplied in a second call and trigger an alert. Callers that need independent streams must construct separate engine and pipeline instances.

This is the current contract for the existing API, not a universal requirement for future APIs. No reset mechanism currently exists.