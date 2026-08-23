from threat_detector.detection.engine import DetectionEngine
from threat_detector.detection.rules.ssh_brute_force import SSHBruteForceRule
from threat_detector.normalization.linux_auth import normalize_linux_event
from threat_detector.parsers.linux_auth import parse_line


def test_linux_ssh_failures_trigger_brute_force_alert():
	raw_lines = [
		"Jan  1 00:00:00 web-01 sshd[1001]: Failed password for alice from 203.0.113.50 port 2222",
		"Jan  1 00:00:10 web-01 sshd[1002]: Failed password for alice from 203.0.113.50 port 2222",
		"Jan  1 00:00:20 web-01 sshd[1003]: Failed password for alice from 203.0.113.50 port 2222",
		"Jan  1 00:00:30 web-01 sshd[1004]: Failed password for alice from 203.0.113.50 port 2222",
		"Jan  1 00:00:40 web-01 sshd[1005]: Failed password for alice from 203.0.113.50 port 2222",
	]
	engine = DetectionEngine([SSHBruteForceRule()])
	alerts = []

	for second, raw_line in zip((0, 10, 20, 30, 40), raw_lines):
		parsed = parse_line(raw_line)
		assert parsed is not None
		normalized = normalize_linux_event(parsed)
		normalized.timestamp = f"2026-01-01T00:00:{second:02d}"
		alerts.append(engine.process(normalized))

	assert alerts[:4] == [[], [], [], []]
	assert len(alerts[4]) == 1

	alert = alerts[4][0]
	assert alert.rule_id == "ssh_brute_force"
	assert alert.source_ip == "203.0.113.50"
	assert alert.raw_events == raw_lines


def test_successful_linux_ssh_authentication_does_not_alert():
	successful_line = (
		"Jan  1 00:00:50 web-01 sshd[1006]: Accepted password for alice "
		"from 203.0.113.50 port 2222"
	)
	engine = DetectionEngine([SSHBruteForceRule()])

	parsed = parse_line(successful_line)

	assert parsed is None
	successful_alerts = []
	if parsed is not None:
		successful_alerts = engine.process(normalize_linux_event(parsed))

	assert successful_alerts == []
