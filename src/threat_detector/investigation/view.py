from threat_detector.alerts.models import Alert
from threat_detector.correlation.models import Finding
from threat_detector.investigation.models import (
    EntityKind,
    EntityRef,
    FindingTimeline,
    FindingView,
    TimelineEntry,
)
from threat_detector.normalization.event import NormalizedEvent


def _alert_entry(alert: Alert) -> TimelineEntry:
    return TimelineEntry(
        timestamp=alert.timestamp,
        kind="alert",
        source_label=alert.rule_id,
        description=alert.description,
        source_ip=alert.source_ip,
        username=alert.username,
    )


def _event_summary(event: NormalizedEvent) -> str:
    parts = [event.event_type]
    if event.service is not None:
        parts.append(f"service={event.service}")
    if event.success is not None:
        parts.append(f"success={event.success}")
    if event.source_ip is not None:
        parts.append(f"source_ip={event.source_ip}")
    return " ".join(parts)


def _event_entry(event: NormalizedEvent) -> TimelineEntry:
    return TimelineEntry(
        timestamp=event.timestamp,
        kind="event",
        source_label=event.event_type,
        description=_event_summary(event),
        source_ip=event.source_ip,
        username=event.username,
    )


def build_timeline(finding: Finding) -> FindingTimeline:
    # Alerts sort before events at an equal timestamp; alerts tie-break on
    # alert_id, events tie-break on their original contributing_events order,
    # since NormalizedEvent has no stable identifier to expose.
    alert_items = [
        ((alert.timestamp, 0, alert.alert_id), _alert_entry(alert))
        for alert in finding.contributing_alerts
    ]
    event_items = [
        ((event.timestamp, 1, index), _event_entry(event))
        for index, event in enumerate(finding.contributing_events)
    ]
    ordered = sorted(alert_items + event_items, key=lambda item: item[0])
    entries = tuple(entry for _, entry in ordered)
    return FindingTimeline(finding_id=finding.finding_id, entries=entries)


def _collect_entities(finding: Finding) -> tuple[EntityRef, ...]:
    seen: set[tuple[EntityKind, str]] = set()
    entities: list[EntityRef] = []

    def add(kind: EntityKind, value: str | None) -> None:
        if value is None:
            return
        key = (kind, value)
        if key in seen:
            return
        seen.add(key)
        entities.append(EntityRef(kind=kind, value=value))

    add("source_ip", finding.source_ip)
    add("username", finding.username)
    for alert in finding.contributing_alerts:
        add("source_ip", alert.source_ip)
        add("username", alert.username)
    for event in finding.contributing_events:
        add("source_ip", event.source_ip)
        add("username", event.username)

    return tuple(entities)


def build_finding_view(finding: Finding) -> FindingView:
    return FindingView(
        finding_id=finding.finding_id,
        finding_type=finding.finding_type,
        severity=finding.severity,
        title=finding.title,
        description=finding.description,
        timestamp=finding.timestamp,
        entities=_collect_entities(finding),
        timeline=build_timeline(finding),
        evidence=finding.evidence,
    )
