# Alert Semantics

This document records the current contracts for `Alert` objects and downstream `Finding` objects. Findings can be persisted; persistence does not change Alert semantics or introduce incident-management behavior.

## Alert as an Instantaneous Detection Result

An `Alert` currently represents an instantaneous detection result or snapshot. It records why a detection rule emitted an alert at a particular event timestamp.

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

For Web Reconnaissance alerts, the normalized suspicious paths embedded in the alert identity, human-readable evidence, and raw event evidence use one deterministic sorted order.

Replacing the current rule-generated IDs with UUIDs has intentionally not been done. No UUID requirement has been established at the current project stage.

## Rule Suppression vs Alert Lifecycle

Stateful rule suppression is internal detection state. It prevents repeated alerts for the same source while the active detection state remains above threshold.

Suppression does not update, extend, resolve, or otherwise change an existing `Alert` object. When suppression clears after watermark-driven expiration, a later threshold crossing can produce a separate detection alert.

## Multiple Rules

Detection rules operate independently. Separate rules may emit separate alerts for overlapping activity, even when the alerts describe the same underlying events.

These alerts retain their own rule identities and are not globally deduplicated by `DetectionEngine`.

## Finding as a Correlation Result

A `Finding` is a downstream, additive result produced by the correlation layer. It combines structured evidence from Alerts and, where applicable, NormalizedEvents; it is not another name for an `Alert` and does not change Alert semantics. An `Alert` is an instantaneous output of a detection rule. A `Finding` is a correlation output that can be persisted.

The current Finding types are:

* `credential_attack_success`: an `ssh_brute_force` alert followed by successful SSH authentication from the same source IP within an inclusive 180-second event-time window. Username matching is not required. The successful event supplies the Finding timestamp, source IP, and username.
* `reconnaissance_credential_attack`: a `web_reconnaissance` alert followed by a `password_spraying` alert from the same source IP within the 180-second window. This represents temporal and source-IP co-occurrence, not proven causation, attacker identity, successful authentication, or compromise.

Correlation state belongs to one `CorrelationEngine` instance. Its watermark is the greatest normalized event timestamp observed, and alerts expire when they are more than 180 seconds behind that watermark. Late successful events can correlate when they remain within the event-time horizon, while a late brute-force alert does not retroactively correlate with a success already processed. Findings preserve contributing objects and deterministic raw-event ordering.

## Persistence

Findings and their contributing evidence can be persisted using separate surrogate database keys. This storage does not add database identity or lifecycle fields to the `Alert` contract.

The `Alert` contract has no database identity, lifecycle fields, incident relationships, or UUID requirement.