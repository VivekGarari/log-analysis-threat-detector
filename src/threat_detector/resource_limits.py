import json
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from typing import Iterable


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """Finite CLI application budgets; byte values use binary KiB/MiB units."""

    max_input_bytes: int = 256 * 1024 * 1024
    max_records: int = 1_000_000
    max_record_bytes: int = 64 * 1024
    windows_xml_max_bytes: int = 16 * 1024 * 1024
    max_alerts: int = 50_000
    max_findings: int = 25_000
    max_result_bytes: int = 128 * 1024 * 1024
    max_report_bytes: int = 64 * 1024 * 1024
    max_persistence_bytes: int = 128 * 1024 * 1024

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{field.name} must be a positive integer")


DEFAULT_RESOURCE_LIMITS = ResourceLimits()


class ResourceLimitExceeded(RuntimeError):
    def __init__(self, resource: str, limit: int, observed: int) -> None:
        self.resource = resource
        self.limit = limit
        self.observed = observed
        super().__init__(
            f"resource limit exceeded: {resource} "
            f"(limit={limit}, observed={observed})"
        )


def _text_bytes(values: Iterable[str | None]) -> int:
    return sum(len(value.encode("utf-8")) for value in values if value is not None)


def _json_array_bytes(values: Iterable[str]) -> int:
    encoder = json.JSONEncoder()
    return sum(len(chunk.encode("utf-8")) for chunk in encoder.iterencode(values))


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def alert_payload_bytes(alert: object) -> int:
    return _text_bytes(
        (
            alert.alert_id,
            alert.rule_id,
            alert.severity,
            alert.title,
            alert.description,
            _timestamp_text(alert.timestamp),
            alert.source_ip,
            alert.username,
        )
    ) + _json_array_bytes(alert.evidence) + _json_array_bytes(alert.raw_events)


def event_payload_bytes(event: object) -> int:
    return _text_bytes(
        (
            _timestamp_text(event.timestamp),
            event.source,
            event.event_type,
            event.hostname,
            event.username,
            event.source_ip,
            str(event.source_port) if event.source_port is not None else None,
            str(int(event.success)) if event.success is not None else None,
            event.raw,
            event.service,
            event.http_path,
        )
    )


def finding_graph_payload_bytes(finding: object) -> int:
    finding_row_bytes = _text_bytes(
        (
            finding.finding_id,
            finding.finding_type,
            finding.severity,
            finding.title,
            finding.description,
            _timestamp_text(finding.timestamp),
            finding.source_ip,
            finding.username,
        )
    ) + _json_array_bytes(finding.evidence) + _json_array_bytes(finding.raw_events)

    return (
        finding_row_bytes
        + sum(alert_payload_bytes(alert) for alert in finding.contributing_alerts)
        + sum(event_payload_bytes(event) for event in finding.contributing_events)
        + (24 * len(finding.contributing_alerts))
        + (24 * len(finding.contributing_events))
    )


def finding_result_payload_bytes(finding: object) -> int:
    finding_row_bytes = _text_bytes(
        (
            finding.finding_id,
            finding.finding_type,
            finding.severity,
            finding.title,
            finding.description,
            _timestamp_text(finding.timestamp),
            finding.source_ip,
            finding.username,
        )
    ) + _json_array_bytes(finding.evidence) + _json_array_bytes(finding.raw_events)
    return finding_row_bytes + sum(
        event_payload_bytes(event) for event in finding.contributing_events
    )


class ResourceBudget:
    def __init__(self, limits: ResourceLimits) -> None:
        self.limits = limits
        self.record_count = 0
        self.alert_count = 0
        self.finding_count = 0
        self.result_bytes = 0
        self.persistence_bytes = 0

    def charge_record(self, record: object) -> None:
        next_count = self.record_count + 1
        if next_count > self.limits.max_records:
            raise ResourceLimitExceeded(
                "input record count", self.limits.max_records, next_count
            )
        record_text = record if isinstance(record, str) else getattr(record, "raw", None)
        if isinstance(record_text, str):
            record_bytes = len(record_text.encode("utf-8"))
            if record_bytes > self.limits.max_record_bytes:
                raise ResourceLimitExceeded(
                    "input record UTF-8 bytes",
                    self.limits.max_record_bytes,
                    record_bytes,
                )
        self.record_count = next_count

    def charge_alert(self, alert: object) -> None:
        next_count = self.alert_count + 1
        next_bytes = self.result_bytes + alert_payload_bytes(alert)
        if next_count > self.limits.max_alerts:
            raise ResourceLimitExceeded("Alert count", self.limits.max_alerts, next_count)
        if next_bytes > self.limits.max_result_bytes:
            raise ResourceLimitExceeded(
                "logical result bytes", self.limits.max_result_bytes, next_bytes
            )
        self.alert_count = next_count
        self.result_bytes = next_bytes

    def charge_finding(self, finding: object) -> None:
        next_count = self.finding_count + 1
        result_bytes = finding_result_payload_bytes(finding)
        graph_bytes = finding_graph_payload_bytes(finding)
        next_result_bytes = self.result_bytes + result_bytes
        next_persistence_bytes = self.persistence_bytes + graph_bytes
        if next_count > self.limits.max_findings:
            raise ResourceLimitExceeded(
                "Finding count", self.limits.max_findings, next_count
            )
        if next_result_bytes > self.limits.max_result_bytes:
            raise ResourceLimitExceeded(
                "logical result bytes", self.limits.max_result_bytes, next_result_bytes
            )
        if next_persistence_bytes > self.limits.max_persistence_bytes:
            raise ResourceLimitExceeded(
                "logical persistence bytes",
                self.limits.max_persistence_bytes,
                next_persistence_bytes,
            )
        self.finding_count = next_count
        self.result_bytes = next_result_bytes
        self.persistence_bytes = next_persistence_bytes
