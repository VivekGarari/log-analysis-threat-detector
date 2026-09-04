# Detection Rule Semantics

This document records the current behavioral contracts for the stateful detection rules. These semantics are enforced by the detection-rule regression tests and should remain explicit during future maintenance.

## Scope

These stateful window semantics apply to `SSHBruteForceRule` and `PasswordSprayingRule`.

`InvalidUserRule` is stateless and does not use event-time windows, watermark expiration, or suppression state.

## Stateful Detection Windows

The stateful rules use a 60-second event-time window.

* The boundary is inclusive: an event exactly 60 seconds from the current watermark is still inside the window.
* Events are evaluated using their event timestamps, not wall-clock arrival time.
* The watermark is the greatest event timestamp observed by the rule.
* State expiration is watermark-driven. Entries expire when the watermark advances beyond their 60-second lifetime; there is no wall-clock timer in the rule.

An event older than the watermark cutoff is stale and is ignored. In other words, an event with a timestamp earlier than `watermark - 60 seconds` does not enter active state.

## SSH Brute Force

`SSHBruteForceRule` groups qualifying SSH authentication-failure events by source IP.

* Five qualifying `authentication_failure` events from one source IP trigger an alert.
* Each qualifying event counts independently, including duplicate events.
* Username is not part of the grouping key and does not affect the count.
* Events from different source IPs are counted independently.
* After an alert, further qualifying events for that IP are suppressed while the active state remains at or above the threshold.
* When expiration reduces the active state below the threshold, suppression clears.
* A later sequence from the same source IP can therefore produce a new alert after the earlier state expires.

## Password Spraying

`PasswordSprayingRule` groups activity by source IP and counts distinct usernames.

* Five distinct usernames from one source IP within the window trigger an alert.
* Repeated attempts for the same username do not increase the distinct-user count.
* Both `authentication_failure` and `invalid_user` events qualify.
* Events from different source IPs are counted independently.
* After an alert, further qualifying events for that IP are suppressed while the active state remains at or above the threshold.
* Expiration removes usernames from the active state and clears suppression when the state falls below the threshold.
* Usernames from an expired window cannot contribute to a later alert.

## Out-of-Order Events

The rules use the event-time watermark rather than assuming that events arrive chronologically.

* An out-of-order event can be accepted when its timestamp is still within the active watermark window.
* An event older than the watermark cutoff is ignored and cannot corrupt active state.

## Why These Semantics Matter

These behaviors are detection contracts, not incidental implementation details. Changes to window boundaries, timestamp handling, grouping keys, duplicate handling, suppression, or expiration can change which activity produces an alert. Refactoring the rules should preserve these semantics unless the detection contract is intentionally revised and its regression tests are updated with it.
