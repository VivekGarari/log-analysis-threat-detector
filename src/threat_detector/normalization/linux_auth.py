from datetime import datetime, timezone

from threat_detector.normalization.event import NormalizedEvent
from threat_detector.parsers.linux_auth import LinuxAuthEvent


def normalize_linux_event(
    event: LinuxAuthEvent, reference_datetime: datetime
) -> NormalizedEvent:
    if reference_datetime.tzinfo is None or reference_datetime.utcoffset() is None:
        raise ValueError("reference_datetime must be timezone-aware")

    if event.event_type == "authentication_success":
        success = True
    elif event.event_type in {"authentication_failure", "invalid_user"}:
        success = False
    else:
        raise ValueError(f"Unsupported Linux auth event type: {event.event_type}")

    timestamp = datetime.strptime(
        f"{reference_datetime.year} {event.timestamp}", "%Y %b %d %H:%M:%S"
    ).replace(tzinfo=reference_datetime.tzinfo).astimezone(timezone.utc)

    return NormalizedEvent(
        timestamp=timestamp,
        source="linux_auth",
        event_type=event.event_type,
        hostname=event.hostname,
        username=event.username,
        source_ip=event.source_ip,
        source_port=event.source_port,
        success=success,
        raw=event.raw,
        service="ssh",
    )
