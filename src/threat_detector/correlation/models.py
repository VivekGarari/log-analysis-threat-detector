from dataclasses import dataclass
from datetime import datetime

from threat_detector.alerts.models import Alert
from threat_detector.normalization.event import NormalizedEvent


@dataclass(frozen=True)
class Finding:
    finding_id: str
    finding_type: str
    severity: str
    title: str
    description: str
    timestamp: datetime
    source_ip: str | None
    username: str | None
    evidence: tuple[str, ...]
    contributing_alerts: tuple[Alert, ...]
    contributing_events: tuple[NormalizedEvent, ...]
    raw_events: tuple[str, ...]
