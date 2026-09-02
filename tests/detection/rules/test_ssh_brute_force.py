from datetime import datetime, timezone

from threat_detector.detection.rules.ssh_brute_force import SSHBruteForceRule
from threat_detector.normalization.event import NormalizedEvent


def make_event(
    timestamp: str,
    *,
    source: str = "linux_auth",
    service: str = "ssh",
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
        service=service,
    )


def timestamp(second: int, *, minute: int = 0) -> str:
	return datetime(2026, 1, 1, 0, minute, second, tzinfo=timezone.utc).isoformat()


def test_four_failures_within_window_produce_no_alert():
	rule = SSHBruteForceRule()

	alerts = [
		rule.process(make_event(timestamp(second)))
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
		rule.process(make_event(timestamp(second)))
		for second in (0, 10, 20, 30, 40)
	]

	assert sum(alert is not None for alert in alerts) == 1
	assert alerts[-1] is not None


def test_additional_failures_do_not_duplicate_alerts():
	rule = SSHBruteForceRule()

	alerts = [
		rule.process(make_event(timestamp(second)))
		for second in (0, 10, 20, 30, 40, 50)
	]

	assert sum(alert is not None for alert in alerts) == 1


def test_failures_from_different_ips_do_not_trigger_rule():
	rule = SSHBruteForceRule()

	alerts = [
		rule.process(
			make_event(
				timestamp(index),
				source_ip=f"192.0.2.{index + 1}",
			)
		)
		for index in range(5)
	]

	assert alerts == [None, None, None, None, None]


def test_new_sequence_can_trigger_after_previous_window_expires():
	rule = SSHBruteForceRule()

	for second in (0, 10, 20, 30):
		assert rule.process(make_event(timestamp(second))) is None
	assert rule.process(make_event(timestamp(40))) is not None

	assert rule.process(make_event(timestamp(41, minute=1))) is None
	alerts = [
		rule.process(make_event(timestamp(second, minute=1)))
		for second in (42, 43, 44, 45)
	]

	assert sum(alert is not None for alert in alerts) == 1


def test_non_ssh_authentication_events_are_ignored():
    rule = SSHBruteForceRule()

    for second in range(5):
        assert (
            rule.process(
                make_event(
                    timestamp(second),
                    event_type="invalid_user",
                    service="http",
                )
            )
            is None
        )


def test_non_ssh_authentication_failures_are_ignored():
    rule = SSHBruteForceRule()

    assert (
        rule.process(
            make_event(
                timestamp(0),
                event_type="authentication_failure",
                service="http",
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
					timestamp(second),
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
					timestamp(second),
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
				timestamp(second),
				raw=raw,
			)
		)

	assert alert is not None
	assert alert.raw_events == raw_events
	assert alert.evidence != raw_events
	assert all("Authentication failure from 192.0.2.10" in item for item in alert.evidence)
	assert all("alice" in item for item in alert.evidence)


def test_expired_per_ip_state_is_cleaned_up():
	rule = SSHBruteForceRule()
	first_timestamp = timestamp(0)
	for source_ip in ("198.51.100.1", "198.51.100.2", "198.51.100.3"):
		rule.process(make_event(first_timestamp, source_ip=source_ip))

	rule.process(make_event(timestamp(1, minute=1), source_ip="198.51.100.1"))

	assert set(rule._failures) == {"198.51.100.1"}


def test_partial_expiration_resets_alert_suppression():
	rule = SSHBruteForceRule()
	for second in (0, 10, 20, 30):
		assert rule.process(make_event(timestamp(second))) is None
	assert rule.process(make_event(timestamp(40))) is not None

	assert rule.process(make_event(timestamp(31, minute=1))) is None
	assert "192.0.2.10" not in rule._alerted_ips

	alerts = [
		rule.process(make_event(timestamp(second, minute=1)))
		for second in (32, 33, 34)
	]

	assert alerts[-1] is not None


def test_repeated_events_at_the_same_timestamp_count_independently():
	rule = SSHBruteForceRule()

	alerts = [rule.process(make_event(timestamp(0))) for _ in range(5)]

	assert sum(alert is not None for alert in alerts) == 1


def test_alert_suppression_applies_within_the_active_window():
	rule = SSHBruteForceRule()

	alerts = [rule.process(make_event(timestamp(second))) for second in range(6)]

	assert sum(alert is not None for alert in alerts) == 1


def test_out_of_order_events_within_active_window_are_accepted():
	rule = SSHBruteForceRule()

	alerts = [
		rule.process(make_event(timestamp(second)))
		for second in (40, 0, 10, 20, 30)
	]

	assert alerts[-1] is not None


def test_out_of_order_event_older_than_current_cutoff_is_discarded():
	rule = SSHBruteForceRule()
	current_timestamp = timestamp(40, minute=1)
	rule.process(make_event(current_timestamp))

	rule.process(make_event(timestamp(39, minute=0)))

	assert [event.timestamp for _, event in rule._failures["192.0.2.10"].values()] == [
		current_timestamp
	]


def test_stale_heap_entries_are_ignored_safely():
	rule = SSHBruteForceRule()
	ip_a = "198.51.100.1"
	ip_b = "198.51.100.2"

	rule.process(make_event(timestamp(0), source_ip=ip_a))
	rule.process(make_event(timestamp(1, minute=1), source_ip=ip_b))

	assert ip_a not in rule._failures
	assert rule._expiration_heap

	alerts = [
		rule.process(make_event(timestamp(second, minute=1), source_ip=ip_b))
		for second in (2, 3, 4, 5)
	]

	assert alerts[-1] is not None
