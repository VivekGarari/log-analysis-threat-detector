from collections.abc import Iterable

from threat_detector.alerts.models import Alert
from threat_detector.detection.base import DetectionRule
from threat_detector.normalization.event import NormalizedEvent


class DetectionEngine:

    def __init__(self, rules: Iterable[DetectionRule]) -> None:
        self.rules = list(rules)

    def process(self, event: NormalizedEvent) -> list[Alert]:
        return [
            alert
            for rule in self.rules
            if (alert := rule.process(event)) is not None
        ]