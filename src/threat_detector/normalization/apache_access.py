from datetime import datetime, timezone

from threat_detector.normalization.event import NormalizedEvent
from threat_detector.parsers.apache_access import ApacheAccessEvent


def normalize_apache_access_event(event: ApacheAccessEvent) -> NormalizedEvent:
    try:
        timestamp = datetime.strptime(
            event.timestamp, "%d/%b/%Y:%H:%M:%S %z"
        )
    except ValueError as error:
        raise ValueError("Invalid Apache access timestamp") from error

    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Apache access timestamp must be timezone-aware")

    return NormalizedEvent(
        timestamp=timestamp.astimezone(timezone.utc),
        source="apache_access",
        event_type="http_access",
        hostname=None,
        username=event.username,
        source_ip=event.client_ip,
        source_port=None,
        success=None,
        raw=event.raw,
        service="http",
        http_path=event.path,
    )