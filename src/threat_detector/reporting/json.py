import json
from collections.abc import Iterable

from threat_detector.alerts.models import Alert


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


def report(alerts: Iterable[Alert]) -> str:
    return json.dumps([_serialize_alert(alert) for alert in alerts], sort_keys=True)
