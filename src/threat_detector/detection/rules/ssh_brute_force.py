import heapq
from datetime import datetime, timedelta, timezone

from threat_detector.alerts.models import Alert
from threat_detector.detection.base import DetectionRule
from threat_detector.normalization.event import NormalizedEvent


class SSHBruteForceRule(DetectionRule):
	rule_id = "ssh_brute_force"
	name = "SSH Brute Force"
	severity = "high"
	window_seconds = 60
	threshold = 5

	def __init__(self) -> None:
		self._failures: dict[str, dict[int, tuple[datetime, NormalizedEvent]]] = {}
		self._expiration_heap: list[tuple[datetime, int, str]] = []
		self._alerted_ips: set[str] = set()
		self._next_sequence = 0
		self._max_event_timestamp: datetime | None = None

	def process(self, event: NormalizedEvent) -> Alert | None:
		if (
			event.source != "linux_auth"
			or event.event_type != "authentication_failure"
			or event.source_ip is None
		):
			return None

		timestamp = self._parse_timestamp(event.timestamp)
		if self._max_event_timestamp is None:
			self._max_event_timestamp = timestamp
		else:
			self._max_event_timestamp = max(self._max_event_timestamp, timestamp)

		watermark = self._max_event_timestamp
		cutoff = watermark - timedelta(seconds=self.window_seconds)
		if timestamp < cutoff:
			return None

		while self._expiration_heap and self._expiration_heap[0][0] < watermark:
			_, sequence_id, source_ip = heapq.heappop(self._expiration_heap)
			failures = self._failures.get(source_ip)
			if failures is None:
				continue
			if failures.pop(sequence_id, None) is None:
				continue
			if not failures:
				del self._failures[source_ip]
				self._alerted_ips.discard(source_ip)
			elif len(failures) < self.threshold:
				self._alerted_ips.discard(source_ip)

		sequence_id = self._next_sequence
		self._next_sequence += 1
		failures = self._failures.setdefault(event.source_ip, {})
		failures[sequence_id] = (timestamp, event)
		heapq.heappush(
			self._expiration_heap,
			(
				timestamp + timedelta(seconds=self.window_seconds),
				sequence_id,
				event.source_ip,
			),
		)

		if len(failures) < self.threshold:
			self._alerted_ips.discard(event.source_ip)
			return None

		if event.source_ip in self._alerted_ips:
			return None

		self._alerted_ips.add(event.source_ip)
		events = [failure for _, failure in failures.values()]
		evidence = [
			f"Authentication failure from {failure.source_ip} at {failure.timestamp}"
			f" for user {failure.username or 'unknown'}"
			for failure in events
		]
		raw_events = [failure.raw for failure in events]
		return Alert(
			alert_id=f"{self.rule_id}:{event.source_ip}:{event.timestamp}",
			rule_id=self.rule_id,
			severity=self.severity,
			title="SSH brute-force attack detected",
			description=(
				f"At least {self.threshold} SSH authentication failures were observed "
				f"from {event.source_ip} within {self.window_seconds} seconds."
			),
			timestamp=event.timestamp,
			source_ip=event.source_ip,
			username=event.username,
			evidence=evidence,
			raw_events=raw_events,
		)

	@staticmethod
	def _parse_timestamp(timestamp: str) -> datetime:
		if timestamp.endswith("Z"):
			timestamp = f"{timestamp[:-1]}+00:00"
		try:
			return datetime.fromisoformat(timestamp)
		except ValueError:
			return datetime.strptime(timestamp, "%b %d %H:%M:%S").replace(
				tzinfo=timezone.utc
			)
