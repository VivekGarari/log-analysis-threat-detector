from abc import ABC, abstractmethod

from threat_detector.alerts.models import Alert
from threat_detector.normalization.event import NormalizedEvent


class DetectionRule(ABC):
    rule_id: str
    name: str
    severity: str

    @abstractmethod
    def process(self, event: NormalizedEvent) -> Alert | None:
        """Process one normalized event and optionally return an alert."""
        raise NotImplementedError