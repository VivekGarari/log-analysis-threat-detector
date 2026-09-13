import heapq
import re
from datetime import datetime, timedelta

from threat_detector.alerts.models import Alert
from threat_detector.detection.base import DetectionRule
from threat_detector.normalization.event import NormalizedEvent

_SUSPICIOUS_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"/admin(?:/|$)"),
    re.compile(r"/administrator(?:/|$)"),
    re.compile(r"/phpmyadmin(?:/|$)"),
    re.compile(r"/pma(?:/|$)"),
    re.compile(r"/wp-admin(?:/|$)"),
    re.compile(r"/wp-login(?:\.php)?(?:/|$)"),
    re.compile(r"/\.env(?:/|$)"),
    re.compile(r"/\.git(?:/|$)"),
    re.compile(r"/\.svn(?:/|$)"),
    re.compile(r"/\.htaccess"),
    re.compile(r"/server-status(?:/|$)"),
    re.compile(r"/server-info(?:/|$)"),
    re.compile(r"/cgi-bin/"),
    re.compile(r"/backup(?:s|s\.|/|$)"),
    re.compile(r"\.(?:sql|bak|zip|tar\.gz|dump)$"),
    re.compile(r"/(?:shell|c99|wso)"),
)


def _normalize_path(http_path: str) -> str:
    return http_path.split("?", 1)[0].lower()


def _is_suspicious_path(path: str) -> bool:
    return any(pattern.search(path) for pattern in _SUSPICIOUS_PATH_PATTERNS)


class WebReconnaissanceRule(DetectionRule):
    rule_id = "web_reconnaissance"
    name = "Web Reconnaissance"
    severity = "medium"
    window_seconds = 60
    threshold = 5

    def __init__(self) -> None:
        self._paths: dict[str, dict[str, tuple[datetime, NormalizedEvent]]] = {}
        self._expiration_heap: list[tuple[datetime, int, str, str]] = []
        self._next_sequence = 0
        self._alerted_ips: set[str] = set()
        self._max_event_timestamp: datetime | None = None

    def process(self, event: NormalizedEvent) -> Alert | None:
        if (
            event.event_type != "http_access"
            or event.service != "http"
            or event.source_ip is None
            or event.http_path is None
        ):
            return None

        normalized = _normalize_path(event.http_path)
        if not _is_suspicious_path(normalized):
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

        ip = event.source_ip
        paths = self._paths.setdefault(ip, {})
        current = paths.get(normalized)
        if current is None or timestamp > current[0]:
            paths[normalized] = (timestamp, event)
            sequence = self._next_sequence
            self._next_sequence += 1
            heapq.heappush(
                self._expiration_heap,
                (
                    timestamp + timedelta(seconds=self.window_seconds),
                    sequence,
                    ip,
                    normalized,
                ),
            )

        if len(paths) < self.threshold:
            self._alerted_ips.discard(ip)
            return None

        if ip in self._alerted_ips:
            return None

        self._alerted_ips.add(ip)
        sorted_paths = sorted(paths)
        raw_events = [paths[p][1].raw for p in sorted_paths]
        return Alert(
            alert_id=(
                f"{self.rule_id}:{ip}:{timestamp}:"
                f"{','.join(sorted_paths)}"
            ),
            rule_id=self.rule_id,
            severity=self.severity,
            title="Web reconnaissance detected",
            description=(
                f"Source {ip} requested {len(sorted_paths)} distinct "
                f"suspicious paths within {self.window_seconds} seconds."
            ),
            timestamp=timestamp,
            source_ip=ip,
            username=None,
            evidence=[
                f"Source {ip} requested suspicious path {p} "
                f"at {paths[p][1].timestamp}"
                for p in sorted_paths
            ],
            raw_events=raw_events,
        )

    def _expire(self, cutoff: datetime, watermark: datetime) -> None:
        affected_ips: set[str] = set()
        while self._expiration_heap and self._expiration_heap[0][0] < watermark:
            expiration, _, source_ip, path = heapq.heappop(
                self._expiration_heap
            )
            paths = self._paths.get(source_ip)
            if paths is None:
                continue
            current = paths.get(path)
            if current is None or current[0] + timedelta(seconds=self.window_seconds) != expiration:
                continue
            del paths[path]
            affected_ips.add(source_ip)
            if not paths:
                del self._paths[source_ip]

        for source_ip in affected_ips:
            paths = self._paths.get(source_ip)
            if paths is None or len(paths) < self.threshold:
                self._alerted_ips.discard(source_ip)