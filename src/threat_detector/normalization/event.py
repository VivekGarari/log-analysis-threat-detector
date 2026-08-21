from dataclasses import dataclass


@dataclass
class NormalizedEvent:
    timestamp: str
    source: str
    event_type: str
    hostname: str | None
    username: str | None
    source_ip: str | None
    source_port: int | None
    success: bool | None
    raw: str