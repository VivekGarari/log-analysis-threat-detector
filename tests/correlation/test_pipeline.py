from datetime import datetime, timedelta, timezone

from threat_detector.alerts.models import Alert
from threat_detector.application.pipeline import DetectionPipeline
from threat_detector.correlation.engine import CorrelationEngine
from threat_detector.detection.engine import DetectionEngine
from threat_detector.normalization.event import NormalizedEvent


class EventEngine(DetectionEngine):
    def process(self, event: NormalizedEvent) -> list[Alert]:
        if event.event_type == "authentication_failure":
            return [
                Alert(
                    alert_id="brute-force-1",
                    rule_id="ssh_brute_force",
                    severity="high",
                    title="SSH brute force",
                    description="Repeated failures",
                    timestamp=event.timestamp,
                    source_ip=event.source_ip,
                    username=event.username,
                    evidence=["failures"],
                    raw_events=[event.raw],
                )
            ]
        return []


def test_pipeline_exposes_findings_without_changing_alert_processing():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    normalized_events = {
        "failure": NormalizedEvent(
            timestamp=base,
            source="test",
            event_type="authentication_failure",
            hostname=None,
            username="admin",
            source_ip="192.0.2.10",
            source_port=22,
            success=False,
            raw="failure",
            service="ssh",
        ),
        "success": NormalizedEvent(
            timestamp=base + timedelta(seconds=180),
            source="test",
            event_type="authentication_success",
            hostname=None,
            username="root",
            source_ip="192.0.2.10",
            source_port=22,
            success=True,
            raw="success",
            service="ssh",
        ),
    }

    def parse_record(record: str) -> str:
        return record

    def normalize_record(record: str) -> NormalizedEvent:
        return normalized_events[record]

    pipeline = DetectionPipeline[str](
        parse_record,
        normalize_record,
        EventEngine([]),
        CorrelationEngine(),
    )

    result = pipeline.process_with_findings(["failure", "success"])

    assert len(result.alerts) == 1
    assert len(result.findings) == 1
    assert result.findings[0].username == "root"
    assert pipeline.process([]) == []
