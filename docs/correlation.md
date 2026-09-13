# Correlation Semantics

## V1 Scenario

The correlation layer currently implements one explicit scenario:

```text
ssh_brute_force alert
→ authentication_success event with service=ssh
→ same source IP within 180 seconds
→ credential_attack_success Finding
```

The successful authentication must occur strictly after the Alert timestamp. The 180-second upper boundary is inclusive. A username mismatch is allowed, and the successful event's username is retained as Finding context. Missing source IPs, a different service, or a different event type do not correlate.

## Event-Time State

Each `CorrelationEngine` instance owns its in-memory state for one continuing event stream. State is grouped by source IP. The watermark is the greatest `NormalizedEvent.timestamp` observed; Alert timestamps do not advance it. Alerts expire when `alert.timestamp + 180 seconds < watermark`, so an Alert exactly 180 seconds old remains eligible.

Out-of-order successful events can correlate if they are not older than `watermark - 180 seconds`. A successful event processed before a late brute-force Alert is not revisited. No persistence, global state, or database is used.

## Finding Evidence and Identity

Findings preserve the selected Alert and successful NormalizedEvent as structured tuples. Raw evidence is ordered as the Alert's raw events followed by the successful event's raw value. When several eligible brute-force Alerts exist, the most recent timestamp is selected; equal timestamps use lexicographically greatest `alert_id` for deterministic ordering.

The V1 identity is deterministic:

```text
credential_attack_success:<source_ip>:<alert_id>:<success_timestamp_iso>:<sha256(success_raw)[:16]>
```

The Finding communicates elevated compromise risk and does not claim that compromise is proven. Future correlation scenarios should remain explicit rather than turning this small layer into a generic query or graph system.