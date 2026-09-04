# Alert Semantics

This document records the current contract for `Alert` objects. It describes the detection output that exists today and intentionally does not define persistence or incident-management behavior.

## Alert as a Detection Finding

An `Alert` currently represents an instantaneous detection finding or snapshot. It records why a detection rule emitted a finding at a particular event timestamp.

It is not currently an incident or a lifecycle-managed object. An `Alert` has no active, acknowledged, resolved, or closed state; no lifecycle timestamps; and no update, acknowledgment, resolution, or incident relationship API.

## Alert Timestamp

`Alert.timestamp` is the timestamp of the event that caused the rule to emit the alert.

It does not currently represent:

* attack start time
* attack end time
* wall-clock alert creation time
* incident update time

For stateful rules, the timestamp is the triggering event timestamp within the event-time detection window.

## Alert Identity

`alert_id` is currently a deterministic, rule-generated detection identity token. Its exact composition is defined by each rule and is preserved by the reporters.

The current identity is useful for in-memory processing and reporting. It is not guaranteed to be globally unique and should not yet be treated as a database primary key.

Replacing the current rule-generated IDs with UUIDs has intentionally not been done. No UUID requirement has been established at the current project stage.

## Rule Suppression vs Alert Lifecycle

Stateful rule suppression is internal detection state. It prevents repeated alerts for the same source while the active detection state remains above threshold.

Suppression does not update, extend, resolve, or otherwise change an existing `Alert` object. When suppression clears after watermark-driven expiration, a later threshold crossing can produce a separate detection finding.

## Multiple Rules

Detection rules operate independently. Separate rules may emit separate alerts for overlapping activity, even when the alerts describe the same underlying events.

These findings retain their own rule identities and are not globally deduplicated by `DetectionEngine`.

## Future Persistence

Persistence may eventually require a separate storage identity and/or a lifecycle model. Those decisions are intentionally deferred until persistence is designed.

The current `Alert` contract should not be extended with database identity, lifecycle fields, incident relationships, or UUIDs before those requirements are explicitly decided and documented.