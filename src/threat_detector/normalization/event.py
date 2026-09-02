from dataclasses import dataclass
from datetime import datetime


@dataclass
class NormalizedEvent:
    timestamp: datetime
    source: str
    event_type: str
    hostname: str | None
    username: str | None
    source_ip: str | None
    source_port: int | None
    success: bool | None
    raw: str
    service: str | None = None
