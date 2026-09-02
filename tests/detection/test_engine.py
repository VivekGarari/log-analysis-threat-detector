from datetime import datetime, timezone

from threat_detector.alerts.models import Alert
from threat_detector.detection.base import DetectionRule
from threat_detector.detection.engine import DetectionEngine
from threat_detector.normalization.event import NormalizedEvent


class FakeRule(DetectionRule):
	rule_id = "fake_rule"
	name = "Fake Rule"
	severity = "low"

	def __init__(self, result: Alert | None) -> None:
		self.result = result
		self.received_events: list[NormalizedEvent] = []

	def process(self, event: NormalizedEvent) -> Alert | None:
		self.received_events.append(event)
		return self.result


def make_event() -> NormalizedEvent:
	return NormalizedEvent(
		timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
		source="test",
		event_type="test_event",
		hostname="test-host",
		username="alice",
		source_ip="192.0.2.10",
		source_port=22,
		success=None,
		raw="test raw event",
	)


def make_alert(alert_id: str) -> Alert:
	return Alert(
		alert_id=alert_id,
		rule_id=f"rule_{alert_id}",
		severity="low",
		title=f"Alert {alert_id}",
		description="Test alert",
		timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
		source_ip=None,
		username=None,
		evidence=[],
		raw_events=[],
	)


def test_engine_with_no_rules_returns_empty_list():
	assert DetectionEngine([]).process(make_event()) == []


def test_rule_returning_none_produces_empty_result():
	rule = FakeRule(None)

	assert DetectionEngine([rule]).process(make_event()) == []


def test_rule_returning_alert_produces_one_element_result():
	alert = make_alert("one")

	result = DetectionEngine([FakeRule(alert)]).process(make_event())

	assert result == [alert]


def test_multiple_alerts_are_returned_in_registration_order():
	first_alert = make_alert("first")
	second_alert = make_alert("second")
	rules = [FakeRule(first_alert), FakeRule(second_alert)]

	result = DetectionEngine(rules).process(make_event())

	assert result == [first_alert, second_alert]


def test_multiple_rules_receive_the_same_event():
	event = make_event()
	first_rule = FakeRule(None)
	second_rule = FakeRule(None)

	DetectionEngine([first_rule, second_rule]).process(event)

	assert first_rule.received_events == [event]
	assert second_rule.received_events == [event]
	assert first_rule.received_events[0] is event
	assert second_rule.received_events[0] is event
