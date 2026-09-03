from threat_detector.alerts.models import Alert
from threat_detector.detection.base import DetectionRule
from threat_detector.normalization.event import NormalizedEvent


class InvalidUserRule(DetectionRule):
    rule_id = "invalid_user"
    name = "Invalid User Attempt"
    severity = "medium"

    def process(self, event: NormalizedEvent) -> Alert | None:
        if event.event_type != "invalid_user":
            return None

        username = event.username or "unknown"
        source_ip = event.source_ip or "unknown"
        return Alert(
            alert_id=f"{self.rule_id}:{event.timestamp}:{source_ip}:{username}",
            rule_id=self.rule_id,
            severity=self.severity,
            title="Invalid user authentication attempt detected",
            description=(
                f"An authentication attempt targeted invalid user {username}"
                f" from {source_ip}."
            ),
            timestamp=event.timestamp,
            source_ip=event.source_ip,
            username=event.username,
            evidence=[
                f"Invalid user {username} from {source_ip} at {event.timestamp}"
            ],
            raw_events=[event.raw],
        )