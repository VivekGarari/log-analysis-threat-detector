from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Generic, TypeVar

from threat_detector.alerts.models import Alert
from threat_detector.correlation.engine import CorrelationEngine
from threat_detector.correlation.models import Finding
from threat_detector.detection.engine import DetectionEngine
from threat_detector.normalization.event import NormalizedEvent

ParsedEvent = TypeVar("ParsedEvent")

Parser = Callable[[str], ParsedEvent | None]
Normalizer = Callable[[ParsedEvent], NormalizedEvent]


@dataclass
class ProcessingResult:
    alerts: list[Alert]
    findings: list[Finding]


class DetectionPipeline(Generic[ParsedEvent]):
    def __init__(
        self,
        parser: Parser[ParsedEvent],
        normalizer: Normalizer[ParsedEvent],
        engine: DetectionEngine,
        correlation_engine: CorrelationEngine | None = None,
    ) -> None:
        self.parser = parser
        self.normalizer = normalizer
        self.engine = engine
        self.correlation_engine = correlation_engine

    def process(self, records: Iterable[str]) -> list[Alert]:
        return self._process(records).alerts

    def process_with_findings(self, records: Iterable[str]) -> ProcessingResult:
        return self._process(records)

    def _process(self, records: Iterable[str]) -> ProcessingResult:
        alerts: list[Alert] = []
        findings: list[Finding] = []

        for record in records:
            parsed_event = self.parser(record)
            if parsed_event is None:
                continue

            normalized_event = self.normalizer(parsed_event)
            event_alerts = self.engine.process(normalized_event)
            alerts.extend(event_alerts)
            if self.correlation_engine is not None:
                findings.extend(
                    self.correlation_engine.process(normalized_event, event_alerts)
                )

        return ProcessingResult(alerts=alerts, findings=findings)
