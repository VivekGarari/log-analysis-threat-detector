from dataclasses import dataclass


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    severity: str
    title: str
    description: str
    timestamp: str
    source_ip: str | None
    username: str | None
    evidence: list[str]
    raw_events: list[str]