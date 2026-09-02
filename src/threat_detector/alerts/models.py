from dataclasses import dataclass
from datetime import datetime


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    severity: str
    title: str
    description: str
    timestamp: datetime
    source_ip: str | None
    username: str | None
    evidence: list[str]
    raw_events: list[str]
