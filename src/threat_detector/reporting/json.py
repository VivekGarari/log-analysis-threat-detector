import json
from collections.abc import Iterable

from threat_detector.alerts.models import Alert
from threat_detector.resource_limits import ResourceLimitExceeded


def _serialize_alert(alert: Alert) -> dict[str, object]:
    return {
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "severity": alert.severity,
        "title": alert.title,
        "description": alert.description,
        "timestamp": alert.timestamp.isoformat(),
        "source_ip": alert.source_ip,
        "username": alert.username,
        "evidence": list(alert.evidence),
        "raw_events": list(alert.raw_events),
    }


def report(alerts: Iterable[Alert], *, max_bytes: int | None = None) -> str:
    if max_bytes is None:
        return json.dumps([_serialize_alert(alert) for alert in alerts], sort_keys=True)

    output: list[str] = ["["]
    output_bytes = 1
    if 2 > max_bytes:
        raise ResourceLimitExceeded("report UTF-8 bytes", max_bytes, 2)
    has_items = False
    for alert in alerts:
        prefix = ", " if has_items else ""
        if prefix:
            output.append(prefix)
            output_bytes += len(prefix)
        for chunk in json.JSONEncoder(sort_keys=True).iterencode(_serialize_alert(alert)):
            chunk_bytes = len(chunk.encode("utf-8"))
            attempted_bytes = output_bytes + chunk_bytes
            if attempted_bytes + 1 > max_bytes:
                raise ResourceLimitExceeded(
                    "report UTF-8 bytes", max_bytes, attempted_bytes + 1
                )
            output.append(chunk)
            output_bytes = attempted_bytes
        has_items = True
    output.append("]")
    return "".join(output)
