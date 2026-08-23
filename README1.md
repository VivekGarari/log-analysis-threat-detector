Log Analysis & Threat Detection Engine

A defensive security telemetry and detection-engineering project designed to ingest heterogeneous logs, normalize security events, correlate behavior, identify suspicious activity, and produce explainable alerts.

1. Why I Am Building This

The objective is not to build another regex-based log parser.

The long-term objective is to build a small detection platform that teaches and demonstrates the core concepts behind:

SIEM systems
detection engineering
SOC analysis
security telemetry
event correlation
behavioral detection
incident investigation
threat intelligence
MITRE ATT&CK mapping
eventually high-throughput security processing

The system should answer:

"What happened, how abnormal is it, what evidence supports that conclusion, and what additional telemetry would an analyst need?"

It should not pretend that every alert identifies an attacker with certainty.

2. The Fundamental Problem

Security systems generate enormous quantities of telemetry.

Examples:

Linux authentication logs
Windows Event Logs
Apache/Nginx logs
Firewall logs
DNS logs
Endpoint telemetry
Process creation
File activity
Network connections
Cloud audit logs
Identity-provider logs

A single event rarely proves an attack.

For example:

Failed SSH login

could mean:

a user typed the wrong password
a legitimate administrator forgot credentials
a vulnerability scanner is probing the host
an attacker is brute-forcing the account

The detection engine therefore needs context.

3. Core Design Philosophy

The project follows five principles.

3.1 Evidence before conclusion

The engine should never simply say:

ATTACKER DETECTED

Instead:

Suspicious authentication activity

Evidence:
- 17 authentication failures
- 6 distinct source IPs
- same target account
- 42-second window
- successful authentication followed the failures

Confidence:
HIGH

Potential technique:
MITRE ATT&CK T1110
3.2 Behavior over identity

An IP address is not an attacker.

An IP can belong to:

a VPN
NAT infrastructure
a corporate gateway
a cloud provider
Tor
a compromised machine
a proxy
a legitimate user

Therefore:

IP reputation = signal

not:

IP reputation = proof
3.3 Correlation over isolated events

The engine should gradually move from:

event → rule → alert

toward:

event
 ↓
event
 ↓
event
 ↓
correlation
 ↓
behavior
 ↓
risk
 ↓
alert
3.4 Explainability

Every alert should eventually answer:

WHAT happened?
WHEN?
WHERE?
WHO/WHAT was involved?
WHY was it suspicious?
WHAT evidence caused the detection?
WHICH rule fired?
WHAT ATT&CK technique might apply?
WHAT information is missing?
3.5 Detection is not attribution

The system can detect:

"This behavior is highly suspicious."

It cannot necessarily determine:

"Person X in country Y performed this attack."

That distinction is fundamental.

4. Architecture

Current architecture:

                    LOG SOURCES
                        │
        ┌───────────────┼────────────────┐
        │               │                │
      Linux           Apache          Windows
        │               │                │
        └───────────────┼────────────────┘
                        ▼
                   INGESTION
                        │
                        ▼
                     PARSERS
                        │
                        ▼
                  NORMALIZATION
                        │
                        ▼
               NORMALIZED EVENTS
                        │
                        ▼
                DETECTION ENGINE
                        │
             ┌──────────┴──────────┐
             ▼                     ▼
       RULE DETECTION         CORRELATION
             │                     │
             └──────────┬──────────┘
                        ▼
                      ALERT
                        │
              ┌─────────┼─────────┐
              ▼         ▼         ▼
             CLI       JSON      Future SIEM
5. Current MVP

The first MVP intentionally starts small.

Currently implemented
Reader
   ↓
Linux auth parser
   ↓
LinuxAuthEvent
   ↓
NormalizedEvent

The first detection target:

SSH brute force

Example:

10:00:01 failure
10:00:05 failure
10:00:09 failure
10:00:13 failure
10:00:17 failure

Five failures from the same source in a short window should produce a detection.

6. Detection Roadmap
Authentication
SSH brute force

Detect repeated failures from a source.

Distributed brute force

Detect many sources collectively targeting the same account/service.

Password spraying

Detect relatively low-volume attempts distributed across many accounts.

This deserves special attention because Microsoft's 2025 Digital Defense Report says password spraying represented 97% of the identity attacks it observed.

Successful authentication after failures

Correlation:

multiple failures
       ↓
successful login
       ↓
higher risk
Invalid-user enumeration

Detect repeated attempts against nonexistent accounts.

Privileged account activity

Monitor unexpected authentication involving privileged identities.

7. Distributed Attack Problem

A naïve detector might implement:

if IP has > 5 failures:
    alert

That is inadequate.

An attacker could generate:

IP1 → 2 attempts
IP2 → 2 attempts
IP3 → 2 attempts
IP4 → 2 attempts
...

No individual IP crosses the threshold.

Therefore we need multiple dimensions:

source count
       +
target concentration
       +
time window
       +
failure rate
       +
account diversity
       +
service

Example:

7,000 source addresses
        ↓
same authentication service
        ↓
same small set of accounts
        ↓
large failure ratio
        ↓
10 minutes
        ↓
DISTRIBUTED AUTHENTICATION ATTACK
8. DDoS / Traffic Flooding

This is a different detection family.

We should not confuse:

authentication attack

with:

availability attack

The detector eventually needs aggregate network/application telemetry such as:

requests/sec
connections/sec
packets/sec
bytes/sec
unique source count
unique destination count
HTTP status distribution
endpoint concentration
protocol distribution

Real-world scale demonstrates why application-local detection isn't enough.

Cloudflare reported that it automatically mitigated 47.1 million DDoS attacks in 2025, averaging 5,376 attacks per hour. One disclosed attack reached 31.4 Tbps, while another campaign exceeded 200 million requests/sec.

Cloudflare also documented attacks where traffic was distributed and randomized across packet attributes, yet its autonomous systems still detected and mitigated them.

Lesson for our project

We shouldn't build:

bad IP → block IP

We should build toward:

traffic fingerprint
+
rate anomaly
+
source diversity
+
target concentration
+
protocol behavior
+
historical baseline
9. Why IP-Based Detection Has Limits

The engine cannot reliably answer:

"Who owns this IP?"

An IP may be:

NAT
VPN
Tor exit
cloud infrastructure
compromised machine
proxy
corporate gateway
residential connection

Therefore we should collect:

source IP
ASN
network/provider
geolocation
reputation
connection history
behavior

but treat them as contextual evidence.

10. Low-and-Slow Attacks

A sophisticated attacker doesn't necessarily generate:

100,000 events/sec

They might generate:

1 event
...
1 event
...
1 event
...

over a much longer period.

Therefore our future engine needs multiple windows:

5 seconds
1 minute
10 minutes
1 hour
24 hours

and eventually behavioral baselines.

11. Covert Data Theft / Exfiltration

This is one of the most difficult problems.

A simplistic detector might look for:

huge upload

But sophisticated exfiltration does not necessarily require one enormous transfer.

Therefore we need to correlate:

file access
      ↓
unusual process activity
      ↓
staging
      ↓
compression/encryption
      ↓
new outbound connection
      ↓
repeated outbound transfers

The critical principle:

Network volume alone is insufficient.

A 10 MB upload may be completely normal.

A 10 MB upload from a previously unseen process after that process accesses hundreds of sensitive files may be considerably more interesting.

12. Endpoint Visibility Limitation

Our engine cannot detect information that our telemetry doesn't contain.

If the system only provides:

firewall.log

we cannot magically determine:

which file was accessed
which process accessed it
which user opened it

Therefore the project should eventually support multiple telemetry sources:

Network
+
Authentication
+
Process
+
File
+
Identity
+
Application

The richer the telemetry, the stronger the correlation.

13. Why Attackers Can Be Hard to Trace

Attribution can become difficult because activity can pass through multiple layers of infrastructure.

Conceptually:

operator
   ↓
intermediary infrastructure
   ↓
compromised hosts / proxy infrastructure
   ↓
target

The detector therefore shouldn't make attribution its primary objective.

Instead:

Detection
   ↓
Evidence
   ↓
Containment
   ↓
Investigation
   ↓
Attribution

Attribution belongs primarily to the investigation process.

14. Detection vs Mitigation

This project is initially a detection engine.

It should not pretend to be a complete DDoS mitigation service.

Large-scale providers operate defenses at network edges and across globally distributed infrastructure. Cloudflare's 2025 reports are a useful example: attacks were detected and mitigated automatically across its network rather than relying solely on the customer's application server.

Our architecture should eventually support integration with:

firewall
WAF
reverse proxy
load balancer
CDN
cloud security controls
SIEM/SOAR

rather than trying to replace all of them.

15. Real-World Incident Lessons
Case Study: Cloudflare / Aisuru

Cloudflare documented the Aisuru botnet generating enormous distributed attacks, including attacks reaching 29.7 Tbps and 14.1 billion packets/sec in Q3 2025. The attacks also randomized packet attributes.

What we learn

A detector must not depend on:

fixed signature
single IP
single packet attribute

It needs:

traffic characteristics
+
aggregation
+
fingerprinting
+
adaptive detection
Case Study: Lumma Stealer

Microsoft's Digital Crimes Unit worked with the U.S. Department of Justice, Europol and Japan's Cybercrime Control Center in a 2025 disruption operation against Lumma Stealer infrastructure. Microsoft reported that more than 2,300 malicious domains were seized or blocked.

What we learn

A mature security response is not:

detect malware

and stop.

It can involve:

endpoint telemetry
+
threat intelligence
+
infrastructure analysis
+
domain intelligence
+
law enforcement
+
infrastructure disruption

Our project should therefore eventually distinguish:

Detection
Investigation
Threat Intelligence
Response

rather than pretending one Python process does everything.

16. Detection Rule Philosophy

Every rule should contain:

Rule ID
Name
Purpose
Data sources
Trigger condition
Time window
Threshold
Severity
Evidence
False positives
False negatives
ATT&CK mapping
Tests

Example:

Rule ID:
AUTH-001

Name:
SSH Brute Force

Data:
Linux auth logs

Trigger:
≥5 failed authentication events
from one source within 60 seconds

Severity:
Medium/High

Evidence:
timestamp
source IP
username
event count
raw events
17. False Positives

Every rule can generate false positives.

Examples:

penetration testing
vulnerability scanners
administrator mistakes
monitoring systems
automated deployment
legitimate service accounts
corporate NAT

Therefore:

Detection ≠ Incident

An alert means:

"Investigate this behavior."

Not:

"This machine is definitely compromised."

18. False Negatives

A detection engine can also miss attacks.

Reasons include:

missing telemetry
encrypted traffic
new attack technique
distributed activity
low-and-slow behavior
legitimate-looking traffic
insufficient historical baseline
log loss
parser failure

This is why the README should explicitly track known blind spots.

19. Risk Scoring

Eventually:

                 ┌──────────────┐
                 │ Authentication│
                 └──────┬───────┘
                        │
                 suspicious
                        │
                 ┌──────▼───────┐
                 │ Network      │
                 │ anomaly      │
                 └──────┬───────┘
                        │
                 suspicious
                        │
                 ┌──────▼───────┐
                 │ Endpoint     │
                 │ activity     │
                 └──────┬───────┘
                        │
                        ▼
                  RISK SCORE

But the score must remain explainable.

No black-box "AI says 87% malicious" nonsense in the first version.

20. MITRE ATT&CK

Eventually detections should map to ATT&CK techniques.

Example:

Password spraying
       ↓
T1110.003

Brute-force detection can map to the appropriate T1110 sub-technique depending on what the evidence actually shows.

This allows alerts to communicate in terminology familiar to SOC and detection-engineering teams.

21. Python → Rust

The first implementation stays Python.

Why?

Because we need a correct reference implementation before optimization.

Later we benchmark:

events/sec
CPU
memory
latency
throughput

If ingestion or aggregation becomes the bottleneck:

Python
   ↓
profiling
   ↓
actual bottleneck
   ↓
Rust implementation

Possible future Rust responsibilities:

high-speed ingestion
stream parsing
event filtering
aggregation
rolling counters
high-throughput preprocessing

Python remains useful for:

orchestration
rules
configuration
analysis
reporting
experimentation
22. Future Architecture

Eventually:

                 TELEMETRY
                     │
                     ▼
              ┌─────────────┐
              │ RUST STREAM │
              │ PROCESSING  │
              └──────┬──────┘
                     │
                     ▼
              NORMALIZED EVENTS
                     │
                     ▼
              ┌──────────────┐
              │ DETECTION    │
              │ ENGINE       │
              └──────┬───────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
    Rules       Correlation    Baselines
        │            │            │
        └────────────┼────────────┘
                     ▼
                 Risk Score
                     │
                     ▼
                   Alert
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
         CLI        SIEM       SOAR
23. What This Project Will NOT Claim

This project will not claim to:

identify every attacker
defeat Tor
defeat VPNs
attribute attacks with certainty
stop every DDoS
inspect encrypted traffic magically
detect attacks without telemetry
replace a production SIEM
replace EDR
replace a WAF
replace a SOC
automatically classify everything with AI

Those claims would make the project look amateurish.

The goal is instead:

Build a defensible, explainable detection pipeline and progressively expand its telemetry, correlation, scale and response capabilities.

24. The Long-Term Vision

The project eventually becomes more than:

log parser

It becomes:

Security Telemetry
       ↓
Normalization
       ↓
Feature Extraction
       ↓
Detection
       ↓
Correlation
       ↓
Risk Assessment
       ↓
Evidence
       ↓
Investigation
       ↓
Response Integration

That is the direction I would take.

And importantly, this should remain a defensive research project. We'll reproduce attack patterns using synthetic logs, isolated lab machines, or controlled datasets rather than experimenting against real systems.


Why I want this README to be different

Most student cybersecurity repositories say:

"This project detects brute-force attacks using Python."

That's weak.

Ours should eventually be able to say:

"The initial detector identifies authentication abuse from normalized Linux telemetry. The architecture deliberately separates parsing, normalization, detection, correlation, evidence, and response integration. The project documents where source attribution fails, why distributed attacks defeat naïve per-IP thresholds, why DDoS requires edge-level mitigation, why low-and-slow exfiltration requires cross-domain telemetry, and how the architecture evolves toward behavioral detection and high-throughput processing."