from collections.abc import Callable, Iterable
from typing import Generic, TypeVar

from threat_detector.alerts.models import Alert
from threat_detector.detection.engine import DetectionEngine
from threat_detector.normalization.event import NormalizedEvent

ParsedEvent = TypeVar("ParsedEvent")

Parser = Callable[[str], ParsedEvent | None]
Normalizer = Callable[[ParsedEvent], NormalizedEvent]


class DetectionPipeline(Generic[ParsedEvent]):
    def __init__(
        self,
        parser: Parser[ParsedEvent],
        normalizer: Normalizer[ParsedEvent],
        engine: DetectionEngine,
    ) -> None:
        self.parser = parser
        self.normalizer = normalizer
        self.engine = engine

    def process(self, records: Iterable[str]) -> list[Alert]:
        alerts: list[Alert] = []

        for record in records:
            parsed_event = self.parser(record)
            if parsed_event is None:
                continue

            normalized_event = self.normalizer(parsed_event)
            alerts.extend(self.engine.process(normalized_event))

        return alerts
