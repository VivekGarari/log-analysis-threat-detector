from datetime import datetime, timezone

from threat_detector.normalization.event import NormalizedEvent
from threat_detector.parsers.windows_security import WindowsSecurityAuthEvent


def normalize_windows_security_event(
    event: WindowsSecurityAuthEvent,
) -> NormalizedEvent:
    if event.event_id == 4624:
        event_type = "authentication_success"
        success = True
    elif event.event_id == 4625:
        event_type = "authentication_failure"
        success = False
    else:
        raise ValueError(
            f"Unsupported Windows Security event ID: {event.event_id}"
        )

    if event.timestamp is None:
        raise ValueError("Windows Security event is missing SystemTime")

    timestamp_text = event.timestamp.replace("Z", "+00:00")
    try:
        timestamp = datetime.fromisoformat(timestamp_text)
    except ValueError as error:
        raise ValueError("Invalid Windows Security SystemTime") from error

    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Windows Security SystemTime must be timezone-aware")

    return NormalizedEvent(
        timestamp=timestamp.astimezone(timezone.utc),
        source="windows_security",
        event_type=event_type,
        hostname=event.hostname,
        username=event.username,
        source_ip=event.source_ip,
        source_port=event.source_port,
        success=success,
        raw=event.raw,
        service=None,
    )