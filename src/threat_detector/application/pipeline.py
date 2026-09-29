from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Generic, TypeVar

from threat_detector.alerts.models import Alert
from threat_detector.correlation.engine import CorrelationEngine
from threat_detector.correlation.models import Finding
from threat_detector.detection.engine import DetectionEngine
from threat_detector.normalization.event import NormalizedEvent
from threat_detector.resource_limits import (
    DEFAULT_RESOURCE_LIMITS,
    ResourceBudget,
    ResourceLimits,
)

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

    def process(
        self,
        records: Iterable[str],
        limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS,
    ) -> list[Alert]:
        return self._process(records, ResourceBudget(limits)).alerts

    def process_with_findings(
        self,
        records: Iterable[str],
        limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS,
    ) -> ProcessingResult:
        return self._process(records, ResourceBudget(limits))

    def _process(
        self, records: Iterable[str], budget: ResourceBudget
    ) -> ProcessingResult:
        alerts: list[Alert] = []
        findings: list[Finding] = []

        for record in records:
            budget.charge_record(record)
            parsed_event = self.parser(record)
            if parsed_event is None:
                continue

            normalized_event = self.normalizer(parsed_event)
            event_alerts = self.engine.process(normalized_event)
            for alert in event_alerts:
                budget.charge_alert(alert)
                alerts.append(alert)
            if self.correlation_engine is not None:
                event_findings = self.correlation_engine.process(
                    normalized_event, event_alerts
                )
                for finding in event_findings:
                    budget.charge_finding(finding)
                    findings.append(finding)

        return ProcessingResult(alerts=alerts, findings=findings)
