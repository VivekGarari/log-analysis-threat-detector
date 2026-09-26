from datetime import datetime, timedelta
from hashlib import sha256

from threat_detector.alerts.models import Alert
from threat_detector.correlation.models import Finding
from threat_detector.normalization.event import NormalizedEvent


class CorrelationEngine:
    CORRELATION_WINDOW = timedelta(seconds=180)

    def __init__(self) -> None:
        self._alerts_by_source_ip: dict[str, list[Alert]] = {}
        self._recon_alerts_by_source_ip: dict[str, list[Alert]] = {}
        self._watermark: datetime | None = None

    def process(
        self,
        event: NormalizedEvent,
        alerts: list[Alert],
    ) -> list[Finding]:
        self._advance_watermark(event.timestamp)
        self._expire_alerts()
        self._expire_recon_alerts()

        findings = self._correlate_success(event)
        findings.extend(self._correlate_password_spraying(alerts))
        self._remember_brute_force_alerts(alerts)
        self._remember_recon_alerts(alerts)
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

    def _expire_recon_alerts(self) -> None:
        if self._watermark is None:
            return

        for source_ip, alerts in list(self._recon_alerts_by_source_ip.items()):
            retained = [
                alert
                for alert in alerts
                if alert.timestamp + self.CORRELATION_WINDOW >= self._watermark
            ]
            if retained:
                self._recon_alerts_by_source_ip[source_ip] = retained
            else:
                del self._recon_alerts_by_source_ip[source_ip]

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

    def _correlate_password_spraying(self, alerts: list[Alert]) -> list[Finding]:
        findings: list[Finding] = []
        for alert in alerts:
            if alert.rule_id != "password_spraying" or alert.source_ip is None:
                continue

            eligible_recon_alerts = [
                recon_alert
                for recon_alert in self._recon_alerts_by_source_ip.get(
                    alert.source_ip, []
                )
                if recon_alert.timestamp < alert.timestamp
                and alert.timestamp - recon_alert.timestamp <= self.CORRELATION_WINDOW
            ]
            if not eligible_recon_alerts:
                continue

            selected_recon_alert = max(
                eligible_recon_alerts,
                key=lambda recon_alert: (recon_alert.timestamp, recon_alert.alert_id),
            )
            findings.append(
                self._build_recon_credential_finding(selected_recon_alert, alert)
            )
        return findings

    def _remember_recon_alerts(self, alerts: list[Alert]) -> None:
        for alert in alerts:
            if alert.rule_id != "web_reconnaissance" or alert.source_ip is None:
                continue
            self._recon_alerts_by_source_ip.setdefault(alert.source_ip, []).append(
                alert
            )

    @staticmethod
    def _build_recon_credential_finding(recon_alert: Alert, spray_alert: Alert) -> Finding:
        finding_id = (
            f"reconnaissance_credential_attack:{spray_alert.source_ip}:"
            f"{recon_alert.alert_id}:{spray_alert.alert_id}"
        )
        elapsed = spray_alert.timestamp - recon_alert.timestamp
        evidence = (
            f"Web reconnaissance alert {recon_alert.alert_id} from source IP "
            f"{recon_alert.source_ip}",
            recon_alert.description,
            f"Password spraying alert {spray_alert.alert_id} from source IP "
            f"{spray_alert.source_ip}",
            spray_alert.description,
            (
                "Password spraying followed web reconnaissance from the same "
                f"source IP by {elapsed.total_seconds():g} seconds"
            ),
            (
                "This reflects temporal and source-IP co-occurrence only; it does "
                "not prove causation, a single attacker, successful authentication, "
                "or compromise."
            ),
        )
        return Finding(
            finding_id=finding_id,
            finding_type="reconnaissance_credential_attack",
            severity="high",
            title="Web reconnaissance followed by password spraying",
            description=(
                "Web reconnaissance and password-spraying activity were observed "
                "from the same source IP within 180 seconds, consistent with a "
                "reconnaissance-to-credential-attack pattern. This does not "
                "indicate successful authentication or confirmed compromise, and "
                "source IP does not establish attacker identity."
            ),
            timestamp=spray_alert.timestamp,
            source_ip=spray_alert.source_ip,
            username=None,
            evidence=evidence,
            contributing_alerts=(recon_alert, spray_alert),
            contributing_events=(),
            raw_events=tuple(recon_alert.raw_events) + tuple(spray_alert.raw_events),
        )

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
