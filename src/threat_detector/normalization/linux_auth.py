from threat_detector.normalization.event import NormalizedEvent
from threat_detector.parsers.linux_auth import LinuxAuthEvent


def normalize_linux_event(event: LinuxAuthEvent) -> NormalizedEvent:
    if event.event_type == "authentication_success":
        success = True
    else:
        success = False

    return NormalizedEvent(
        timestamp=event.timestamp,
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
