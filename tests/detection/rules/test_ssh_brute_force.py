from threat_detector.detection.rules.ssh_brute_force import SSHBruteForceRule
from threat_detector.normalization.event import NormalizedEvent


def make_event(
	timestamp: str,
	*,
	source: str = "linux_auth",
	event_type: str = "authentication_failure",
	source_ip: str | None = "192.0.2.10",
	success: bool | None = False,
	raw: str | None = None,
) -> NormalizedEvent:
	return NormalizedEvent(
		timestamp=timestamp,
		source=source,
		event_type=event_type,
		hostname="server",
		username="alice",
		source_ip=source_ip,
		source_port=22,
		success=success,
		raw=raw or f"raw event at {timestamp}",
	)


def test_four_failures_within_window_produce_no_alert():
	rule = SSHBruteForceRule()

	alerts = [
		rule.process(make_event(f"2026-01-01T00:00:{second:02d}"))
		for second in (0, 10, 20, 30)
	]

	assert alerts == [None, None, None, None]


def test_yearless_syslog_timestamps_trigger_without_unix_timestamp_conversion():
	rule = SSHBruteForceRule()

	alerts = [
		rule.process(make_event(f"Jan  1 00:00:{second:02d}"))
		for second in (0, 10, 20, 30, 40)
	]

	assert alerts[:4] == [None, None, None, None]
	assert alerts[4] is not None


def test_fifth_failure_produces_one_alert():
	rule = SSHBruteForceRule()

	alerts = [
		rule.process(make_event(f"2026-01-01T00:00:{second:02d}"))
		for second in (0, 10, 20, 30, 40)
	]

	assert sum(alert is not None for alert in alerts) == 1
	assert alerts[-1] is not None


def test_additional_failures_do_not_duplicate_alerts():
	rule = SSHBruteForceRule()

	alerts = [
		rule.process(make_event(f"2026-01-01T00:00:{second:02d}"))
		for second in (0, 10, 20, 30, 40, 50)
	]

	assert sum(alert is not None for alert in alerts) == 1


def test_failures_from_different_ips_do_not_trigger_rule():
	rule = SSHBruteForceRule()

	alerts = [
		rule.process(
			make_event(
				f"2026-01-01T00:00:{index:02d}",
				source_ip=f"192.0.2.{index + 1}",
			)
		)
		for index in range(5)
	]

	assert alerts == [None, None, None, None, None]


def test_new_sequence_can_trigger_after_previous_window_expires():
	rule = SSHBruteForceRule()

	for second in (0, 10, 20, 30):
		assert rule.process(make_event(f"2026-01-01T00:00:{second:02d}")) is None
	assert rule.process(make_event("2026-01-01T00:00:40")) is not None

	assert rule.process(make_event("2026-01-01T00:01:41")) is None
	alerts = [
		rule.process(make_event(f"2026-01-01T00:01:{second:02d}"))
		for second in (42, 43, 44, 45)
	]

	assert sum(alert is not None for alert in alerts) == 1


def test_non_linux_auth_events_are_ignored():
	rule = SSHBruteForceRule()

	for second in range(5):
		assert (
			rule.process(
				make_event(
					f"2026-01-01T00:00:{second:02d}",
					source="apache",
				)
			)
			is None
		)


def test_successful_authentication_events_are_ignored():
	rule = SSHBruteForceRule()

	for second in range(5):
		assert (
			rule.process(
				make_event(
					f"2026-01-01T00:00:{second:02d}",
					event_type="authentication_success",
					success=True,
				)
			)
			is None
		)


def test_events_without_source_ip_are_ignored():
	rule = SSHBruteForceRule()

	for second in range(5):
		assert (
			rule.process(
				make_event(
					f"2026-01-01T00:00:{second:02d}",
					source_ip=None,
				)
			)
			is None
		)


def test_alert_has_readable_evidence_and_original_raw_events():
	rule = SSHBruteForceRule()
	raw_events = [f"sshd raw line {index}" for index in range(5)]

	alert = None
	for second, raw in zip((0, 10, 20, 30, 40), raw_events):
		alert = rule.process(
			make_event(
				f"2026-01-01T00:00:{second:02d}",
				raw=raw,
			)
		)

	assert alert is not None
	assert alert.raw_events == raw_events
	assert alert.evidence != raw_events
	assert all("Authentication failure from 192.0.2.10" in item for item in alert.evidence)
	assert all("alice" in item for item in alert.evidence)
