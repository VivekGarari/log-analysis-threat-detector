import heapq
from datetime import datetime, timedelta

from threat_detector.alerts.models import Alert
from threat_detector.detection.base import DetectionRule
from threat_detector.normalization.event import NormalizedEvent


class PasswordSprayingRule(DetectionRule):
    rule_id = "password_spraying"
    name = "Password Spraying"
    severity = "high"
    window_seconds = 60
    threshold = 5

    def __init__(self) -> None:
        self._attempts: dict[
            str, dict[str, tuple[datetime, NormalizedEvent]]
        ] = {}
        self._expiration_heap: list[tuple[datetime, int, str, str]] = []
        self._next_sequence = 0
        self._alerted_ips: set[str] = set()
        self._max_event_timestamp: datetime | None = None

    def process(self, event: NormalizedEvent) -> Alert | None:
        if event.event_type not in {
            "authentication_failure",
            "invalid_user",
        }:
            return None
        if event.source_ip is None or event.username is None:
            return None

        timestamp = event.timestamp
        if self._max_event_timestamp is None:
            self._max_event_timestamp = timestamp
        else:
            self._max_event_timestamp = max(self._max_event_timestamp, timestamp)

        watermark = self._max_event_timestamp
        cutoff = watermark - timedelta(seconds=self.window_seconds)
        if timestamp < cutoff:
            return None

        self._expire(cutoff, watermark)

        attempts = self._attempts.setdefault(event.source_ip, {})
        current = attempts.get(event.username)
        if current is None or timestamp > current[0]:
            attempts[event.username] = (timestamp, event)
            sequence = self._next_sequence
            self._next_sequence += 1
            heapq.heappush(
                self._expiration_heap,
                (
                    timestamp + timedelta(seconds=self.window_seconds),
                    sequence,
                    event.source_ip,
                    event.username,
                ),
            )

        if len(attempts) < self.threshold:
            self._alerted_ips.discard(event.source_ip)
            return None

        if event.source_ip in self._alerted_ips:
            return None

        self._alerted_ips.add(event.source_ip)
        usernames = sorted(attempts)
        raw_events = [attempts[username][1].raw for username in usernames]
        username_list = ", ".join(usernames)
        return Alert(
            alert_id=(
                f"{self.rule_id}:{event.source_ip}:{event.timestamp}:"
                f"{','.join(usernames)}"
            ),
            rule_id=self.rule_id,
            severity=self.severity,
            title="Password spraying activity detected",
            description=(
                f"Source {event.source_ip} attempted authentication for "
                f"{len(usernames)} distinct usernames within "
                f"{self.window_seconds} seconds."
            ),
            timestamp=event.timestamp,
            source_ip=event.source_ip,
            username=None,
            evidence=[
                f"Source {event.source_ip} attempted authentication for "
                f"{len(usernames)} distinct usernames within "
                f"{self.window_seconds} seconds: {username_list}."
            ],
            raw_events=raw_events,
        )

    def _expire(self, cutoff: datetime, watermark: datetime) -> None:
        while self._expiration_heap and self._expiration_heap[0][0] < watermark:
            expiration, _, source_ip, username = heapq.heappop(
                self._expiration_heap
            )
            attempts = self._attempts.get(source_ip)
            if attempts is None:
                continue

            current = attempts.get(username)
            if current is None or current[0] + timedelta(seconds=self.window_seconds) != expiration:
                continue

            del attempts[username]
            if not attempts:
                del self._attempts[source_ip]
                self._alerted_ips.discard(source_ip)
            elif len(attempts) < self.threshold:
                self._alerted_ips.discard(source_ip)
