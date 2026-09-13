# Detection Rule Semantics

This document records the current behavioral contracts for the stateful detection rules. These semantics are enforced by the detection-rule regression tests and should remain explicit during future maintenance.

## Scope

These stateful window semantics apply to `SSHBruteForceRule`, `PasswordSprayingRule`, and `WebReconnaissanceRule`.

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

## Web Reconnaissance

`WebReconnaissanceRule` groups Apache access events by source IP and counts distinct suspicious HTTP paths.

* Qualifying events must have `event_type == "http_access"`, `service == "http"`, a non-`None` `source_ip`, and a non-`None` `http_path`.
* The path is normalized before matching: the query string (everything from the first `?` onward) is stripped, and the result is lowercased. Two paths that differ only by query string or case count as the same path.
* A normalized path is considered "suspicious" if it matches any pattern in the V1 reconnaissance signature. The signature is a small, explicit, module-level tuple of compiled regular expressions covering representative categories: administrative interfaces (`/admin`, `/administrator`, `/phpmyadmin`, `/pma`), common CMS administration/login paths (`/wp-admin`, `/wp-login`), exposed configuration/secrets (`/.env`, `/.git`, `/.svn`, `/.htaccess`), server status/info endpoints (`/server-status`, `/server-info`), CGI/script probing (`/cgi-bin/`), backup/archive/database-file probing (`/backup...`, `*.sql`, `*.bak`, `*.zip`, `*.tar.gz`, `*.dump`), and obvious shell/webshell-style probing.
* Five distinct suspicious paths from one source IP within the inclusive 60-second window trigger an alert.
* Repeated requests for the same normalized suspicious path do not increase the distinct-path count.
* Events from different source IPs are counted independently.
* HTTP methods and status codes are intentionally not part of V1 detection logic; only the normalized path determines whether a request contributes to the count.
* After an alert, further qualifying events for that IP are suppressed while the active state remains at or above the threshold.
* Expiration removes paths from the active state and clears suppression when the state falls below the threshold.
* Paths from an expired window cannot contribute to a later alert.
* A later threshold crossing after suppression clears produces a new alert.
* The alert ID path set, evidence entries, and raw event evidence are ordered by the same sorted normalized-path order.
* **Known V1 limitations and false-positive considerations:**
  * The V1 signature is a curated heuristic, not a comprehensive web vulnerability scanner. Real reconnaissance tools that hit many signature-matching paths will be detected; tools that exclusively probe non-signature paths will not.
  * Heavy legitimate administration activity (e.g., a site editor navigating to many admin endpoints in 60 seconds) can produce a false positive. Severity is `medium` to reflect this.
  * The rule does not normalize percent-encoding, path-traversal sequences (`../`), or case-varied segments. Two paths that differ only by percent-encoding are treated as distinct.
  * The rule trusts `source_ip` from the access log; deployments behind a reverse proxy will group on the proxy IP, consistent with other stateful rules.
  * Wordlist-driven scanners can produce hundreds of distinct suspicious paths, which makes the deterministic `alert_id` long. The full sorted path set is included in the `alert_id` for replay determinism.

## Out-of-Order Events

The rules use the event-time watermark rather than assuming that events arrive chronologically.

* An out-of-order event can be accepted when its timestamp is still within the active watermark window.
* An event older than the watermark cutoff is ignored and cannot corrupt active state.

## Why These Semantics Matter

These behaviors are detection contracts, not incidental implementation details. Changes to window boundaries, timestamp handling, grouping keys, duplicate handling, suppression, or expiration can change which activity produces an alert. Refactoring the rules should preserve these semantics unless the detection contract is intentionally revised and its regression tests are updated with it.
