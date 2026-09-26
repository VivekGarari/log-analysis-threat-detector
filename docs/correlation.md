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

## V2 Scenario: Reconnaissance → Credential Attack

The correlation layer also implements a second, independent scenario:

```text
web_reconnaissance alert
→ password_spraying alert
→ same source IP
→ recon_timestamp < spray_timestamp <= recon_timestamp + 180 seconds
→ reconnaissance_credential_attack Finding
```

Both stages are `Alert` objects (not raw events); neither `web_reconnaissance` nor `password_spraying` alerts carry a structured username, so correlation is keyed on `source_ip` alone. The password-spraying alert timestamp must be strictly later than the reconnaissance alert timestamp; equal timestamps do not correlate. The 180-second upper boundary is inclusive and reuses the same `CORRELATION_WINDOW` constant as the V1 scenario.

Reconnaissance alerts are retained per source IP and expire using the same watermark-driven mechanism as V1 brute-force alerts (the greatest observed `NormalizedEvent.timestamp` is the watermark; a reconnaissance alert expires once it is more than 180 seconds behind the watermark). A password-spraying alert processed before any qualifying reconnaissance alert is retained produces no Finding, and this is not revisited later: a reconnaissance alert that arrives after a spraying alert has already been evaluated does not retroactively correlate with it. When several eligible reconnaissance alerts exist for one source IP, the most recent is selected using the same `(timestamp, alert_id)` deterministic rule as V1. Each qualifying password-spraying alert is evaluated independently and may produce its own Finding; V1 does not deduplicate or globally suppress repeated Findings.

The Finding identity is deterministic and does not require a hash, because both contributing alert IDs are already deterministic:

```text
reconnaissance_credential_attack:<source_ip>:<recon_alert_id>:<spray_alert_id>
```

`Finding.timestamp` and `Finding.source_ip` come from the password-spraying alert. `Finding.username` is `None`: a password-spraying alert inherently spans multiple usernames, and V1 does not collapse that into a single identity. `contributing_alerts` is `(recon_alert, spray_alert)`; `contributing_events` is empty, since the correlation is Alert-to-Alert and the individual normalized events behind each alert are not retained. `raw_events` is the reconnaissance alert's raw events followed by the spraying alert's raw events. Evidence is built only from structured `Alert` fields (IDs, source IP, existing `description` text) and never parses `Alert.raw_events` or `NormalizedEvent.raw`.

**This Finding is a co-occurrence signal, not proof of an attack chain.** It indicates only that reconnaissance and password-spraying activity were both observed from the same source IP within the time window. It does not prove that the reconnaissance caused or informed the password spraying, that the same human operated both, or that any authentication succeeded or any account was compromised. Source IP alone is not attacker identity. This is intentionally weaker evidence than the V1 `credential_attack_success` scenario, which correlates against an actual successful authentication event.

## Investigation Projection

`Finding` is the correlation layer's output and remains the source of truth. `threat_detector.investigation` adds a strictly downstream, read-only projection on top of it: `build_finding_view(finding)` returns a `FindingView` containing the Finding's own summary fields, a chronological `FindingTimeline`, and a deduplicated set of `EntityRef` entities (`source_ip`/`username`).

The timeline is built only from `Finding.contributing_alerts` and `Finding.contributing_events` — one `TimelineEntry` per contributing object, ordered by timestamp (alerts before events on a tie). Raw log strings (`Alert.raw_events`, `NormalizedEvent.raw`, `Finding.raw_events`) are deliberately excluded from timeline construction; they are never parsed by this layer.

Because `password_spraying` alerts do not currently carry a structured list of the usernames they observed (`Alert.username` is `None` for that rule), the investigation layer cannot yet represent those usernames as entities. This is a known data-model gap, not something the investigation layer works around by parsing `evidence` or `description` text.

The investigation model does not alter detection or correlation behavior, add persistence, or introduce risk scoring, MITRE mapping, or case-management concepts — it is a pure projection of an existing `Finding`.