from datetime import datetime, timezone

from threat_detector.alerts.models import Alert
from threat_detector.application.pipeline import DetectionPipeline
from threat_detector.detection.engine import DetectionEngine
from threat_detector.normalization.event import NormalizedEvent
from threat_detector.normalization.linux_auth import normalize_linux_event
from threat_detector.parsers.linux_auth import parse_line


class RecordingEngine:
    def __init__(self, alerts_by_event: dict[str, list[Alert]] | None = None) -> None:
        self.alerts_by_event = alerts_by_event or {}
        self.received_events: list[NormalizedEvent] = []

    def process(self, event: NormalizedEvent) -> list[Alert]:
        self.received_events.append(event)
        return self.alerts_by_event.get(event.raw, [])


def make_event(raw: str) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        source="test",
        event_type="test_event",
        hostname="test-host",
        username=None,
        source_ip=None,
        source_port=None,
        success=None,
        raw=raw,
    )


def make_alert(alert_id: str) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id="test_rule",
        severity="low",
        title=f"Alert {alert_id}",
        description="Test alert",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        source_ip=None,
        username=None,
        evidence=[],
        raw_events=[],
    )


def test_valid_record_is_parsed_normalized_detected_and_returned():
    parser_calls: list[str] = []
    normalizer_calls: list[str] = []
    alert = make_alert("one")
    engine = RecordingEngine({"raw": [alert]})

    def parser(record: str) -> str:
        parser_calls.append(record)
        return record.upper()

    def normalizer(parsed_event: str) -> NormalizedEvent:
        normalizer_calls.append(parsed_event)
        return make_event("raw")

    result = DetectionPipeline(parser, normalizer, engine).process(["raw"])

    assert result == [alert]
    assert parser_calls == ["raw"]
    assert normalizer_calls == ["RAW"]
    assert [event.raw for event in engine.received_events] == ["raw"]


def test_parser_returning_none_skips_normalization_and_detection():
    normalized_events: list[str] = []
    engine = RecordingEngine()

    def parser(record: str) -> str | None:
        return None if record == "skip" else record

    def normalizer(parsed_event: str) -> NormalizedEvent:
        normalized_events.append(parsed_event)
        return make_event(parsed_event)

    result = DetectionPipeline(parser, normalizer, engine).process(["skip"])

    assert result == []
    assert normalized_events == []
    assert engine.received_events == []


def test_parser_miss_does_not_stop_later_valid_records():
    parser_calls: list[str] = []
    normalizer_calls: list[str] = []
    alerts = {
        "first": [make_alert("first")],
        "last": [make_alert("last")],
    }
    engine = RecordingEngine(alerts)

    def parser(record: str) -> str | None:
        parser_calls.append(record)
        return None if record == "malformed" else record

    def normalizer(parsed_event: str) -> NormalizedEvent:
        normalizer_calls.append(parsed_event)
        return make_event(parsed_event)

    pipeline = DetectionPipeline(parser, normalizer, engine)

    assert pipeline.process(["first", "malformed", "last"]) == [
        alerts["first"][0],
        alerts["last"][0],
    ]
    assert parser_calls == ["first", "malformed", "last"]
    assert normalizer_calls == ["first", "last"]
    assert [event.raw for event in engine.received_events] == ["first", "last"]


def test_all_parser_misses_return_no_alerts():
    engine = RecordingEngine()
    pipeline = DetectionPipeline(lambda record: None, make_event, engine)

    assert pipeline.process(["malformed-one", "malformed-two"]) == []
    assert engine.received_events == []


def test_multiple_records_and_alerts_preserve_input_and_alert_order():
    first = make_alert("first")
    second = make_alert("second")
    third = make_alert("third")
    engine = RecordingEngine({"one": [first], "two": [second, third]})

    pipeline = DetectionPipeline(
        lambda record: record,
        make_event,
        engine,
    )

    assert pipeline.process(["one", "two"]) == [first, second, third]
    assert [event.raw for event in engine.received_events] == ["one", "two"]


def test_empty_input_returns_empty_list():
    engine = RecordingEngine()
    pipeline = DetectionPipeline(lambda record: record, make_event, engine)

    assert pipeline.process([]) == []
    assert engine.received_events == []


def test_normalizer_exception_propagates_without_calling_engine():
    engine = RecordingEngine()

    def normalizer(parsed_event: str) -> NormalizedEvent:
        raise ValueError(f"invalid {parsed_event}")

    pipeline = DetectionPipeline(lambda record: record, normalizer, engine)

    try:
        pipeline.process(["record"])
    except ValueError as error:
        assert str(error) == "invalid record"
    else:
        raise AssertionError("expected normalizer exception to propagate")

    assert engine.received_events == []


def test_pipeline_state_carries_across_process_calls():
    from datetime import timedelta

    from threat_detector.detection.rules.ssh_brute_force import SSHBruteForceRule

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = {
        str(second): NormalizedEvent(
            timestamp=base + timedelta(seconds=second),
            source="linux_auth",
            event_type="authentication_failure",
            hostname="server",
            username="alice",
            source_ip="192.0.2.10",
            source_port=22,
            success=False,
            raw=str(second),
            service="ssh",
        )
        for second in (0, 10, 20, 30, 40)
    }
    pipeline = DetectionPipeline(
        lambda record: record,
        events.__getitem__,
        DetectionEngine([SSHBruteForceRule()]),
    )

    assert pipeline.process(["0", "10", "20", "30"]) == []
    alerts = pipeline.process(["40"])

    assert len(alerts) == 1
    assert alerts[0].rule_id == "ssh_brute_force"


def test_normalizer_wrapper_can_supply_linux_reference_datetime():
    reference_datetime = datetime(2026, 9, 2, 12, tzinfo=timezone.utc)
    raw_line = (
        "Jan  1 00:00:00 web-01 sshd[1001]: Failed password for alice "
        "from 203.0.113.50 port 2222"
    )
    engine = RecordingEngine()

    def normalizer(parsed_event):
        return normalize_linux_event(parsed_event, reference_datetime)

    DetectionPipeline(parse_line, normalizer, engine).process([raw_line])

    assert len(engine.received_events) == 1
    assert engine.received_events[0].source == "linux_auth"
    assert engine.received_events[0].username == "alice"
    assert engine.received_events[0].timestamp == datetime(
        2026, 1, 1, tzinfo=timezone.utc
    )


def test_real_engine_can_be_supplied_to_pipeline():
    raw_line = (
        "Jan  1 00:00:00 web-01 sshd[1001]: Accepted password for alice "
        "from 203.0.113.50 port 2222"
    )
    reference_datetime = datetime(2026, 9, 2, 12, tzinfo=timezone.utc)
    engine = DetectionEngine([])
    normalizer = lambda event: normalize_linux_event(event, reference_datetime)

    assert DetectionPipeline(parse_line, normalizer, engine).process([raw_line]) == []
