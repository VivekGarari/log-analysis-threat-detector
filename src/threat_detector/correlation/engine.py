from datetime import datetime, timedelta
from hashlib import sha256

from threat_detector.alerts.models import Alert
from threat_detector.correlation.models import Finding
from threat_detector.normalization.event import NormalizedEvent


class CorrelationEngine:
    CORRELATION_WINDOW = timedelta(seconds=180)

    def __init__(self) -> None:
        self._alerts_by_source_ip: dict[str, list[Alert]] = {}
        self._watermark: datetime | None = None

    def process(
        self,
        event: NormalizedEvent,
        alerts: list[Alert],
    ) -> list[Finding]:
        self._advance_watermark(event.timestamp)
        self._expire_alerts()

        findings = self._correlate_success(event)
        self._remember_brute_force_alerts(alerts)
        return findings

    def _advance_watermark(self, timestamp: datetime) -> None:
        if self._watermark is None or timestamp > self._watermark:
            self._watermark = timestamp

    def _expire_alerts(self) -> None:
        if self._watermark is None:
            return

        for source_ip, alerts in list(self._alerts_by_source_ip.items()):
            retained = [
                alert
                for alert in alerts
                if alert.timestamp + self.CORRELATION_WINDOW >= self._watermark
            ]
            if retained:
                self._alerts_by_source_ip[source_ip] = retained
            else:
                del self._alerts_by_source_ip[source_ip]

    def _correlate_success(self, event: NormalizedEvent) -> list[Finding]:
        if (
            event.event_type != "authentication_success"
            or event.service != "ssh"
            or event.source_ip is None
        ):
            return []

        if self._watermark is not None and event.timestamp < (
            self._watermark - self.CORRELATION_WINDOW
        ):
            return []

        eligible_alerts = [
            alert
            for alert in self._alerts_by_source_ip.get(event.source_ip, [])
            if alert.timestamp < event.timestamp
            and event.timestamp - alert.timestamp <= self.CORRELATION_WINDOW
        ]
        if not eligible_alerts:
            return []

        selected_alert = max(
            eligible_alerts,
            key=lambda alert: (alert.timestamp, alert.alert_id),
        )
        return [self._build_finding(selected_alert, event)]

    def _remember_brute_force_alerts(self, alerts: list[Alert]) -> None:
        for alert in alerts:
            if alert.rule_id != "ssh_brute_force" or alert.source_ip is None:
                continue
            self._alerts_by_source_ip.setdefault(alert.source_ip, []).append(alert)

    @staticmethod
    def _build_finding(alert: Alert, event: NormalizedEvent) -> Finding:
        digest = sha256(event.raw.encode("utf-8")).hexdigest()[:16]
        finding_id = (
            f"credential_attack_success:{event.source_ip}:{alert.alert_id}:"
            f"{event.timestamp.isoformat()}:{digest}"
        )
        elapsed = event.timestamp - alert.timestamp
        evidence = (
            f"SSH brute-force detection from source IP {event.source_ip}",
            (
                "Successful SSH authentication for username "
                f"{event.username!r} from source IP {event.source_ip}"
            ),
            f"Successful authentication followed the alert by {elapsed.total_seconds():g} seconds",
        )
        return Finding(
            finding_id=finding_id,
            finding_type="credential_attack_success",
            severity="critical",
            title="Credential attack followed by successful SSH authentication",
            description=(
                "A successful SSH authentication followed brute-force activity from "
                "the same source IP within 180 seconds, indicating elevated compromise risk."
            ),
            timestamp=event.timestamp,
            source_ip=event.source_ip,
            username=event.username,
            evidence=evidence,
            contributing_alerts=(alert,),
            contributing_events=(event,),
            raw_events=tuple(alert.raw_events) + (event.raw,),
        )
